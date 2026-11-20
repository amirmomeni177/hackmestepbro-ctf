# frozen_string_literal: true

require "base64"
require "cgi"
require "digest"
require "fileutils"
require "json"
require "jwt"
require "minitest/autorun"
require "net/http"
require "openssl"
require "socket"
require "stringio"
require "timeout"
require "tmpdir"
require "uri"

class FlowTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  BASE = "/labs/google-signin"
  ORIGIN = "https://lab.test"
  AUTH = "#{BASE}/users/auth/google_oauth2"
  CALLBACK = "#{ORIGIN}#{AUTH}/callback"
  IDP = "#{BASE}/idp"
  LAB_NOTICE = '<a href="/">Lumora is a fictional site — HackMeStepBro reference lab · no flag</a>'
  GRAPHQL = "#{BASE}/graphql"
  FEDCM = "#{IDP}/gsi/fedcm"
  FEDCM_HEADERS = { "Sec-Fetch-Dest" => "webidentity", "Origin" => ORIGIN }.freeze
  FALLBACK_HEADERS = { "Sec-Fetch-Site" => "same-origin", "X-Keystone-One-Tap" => "1", "Origin" => ORIGIN }.freeze
  OAUTH_OPERATION = "SignInWithOAuthMutation"
  PROFILE_UPDATE = <<~GRAPHQL
    mutation UpdateProfile($input: UpdateProfileInput!) {
      updateProfile(input: $input) { currentUser { id name } errors { path message } }
    }
  GRAPHQL

  class << self
    attr_reader :port, :directory

    def start_server
      return if @pid

      @port = TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }
      data_root = File.join(ROOT, "data")
      FileUtils.mkdir_p(data_root, mode: 0o700)
      @directory = Dir.mktmpdir("flow-", data_root)
      log_file = File.join(@directory, "server.log")
      @pid = Process.spawn({ "PORT" => @port.to_s, "PUBLIC_ORIGIN" => ORIGIN, "LAB_DATA_DIR" => @directory },
                           "./start.sh", chdir: ROOT, out: log_file, err: [:child, :out])
      Timeout.timeout(10) do
        loop do
          raise "Puma exited during startup" if Process.waitpid(@pid, Process::WNOHANG)

          begin
            ready = http.get("#{BASE}/me", "Host" => "lab.test", "X-Forwarded-Proto" => "https")
            break if ready.code == "200"
          rescue Errno::ECONNREFUSED
            # Puma is still starting.
          end
          sleep 0.05
        end
      end
    rescue StandardError => error
      log = File.read(log_file) if log_file && File.file?(log_file)
      stop_server
      raise "Server startup failed (#{error.message})\n#{log}"
    end

    def http
      Net::HTTP.new("127.0.0.1", @port, nil).tap do |connection|
        connection.open_timeout = 2
        connection.read_timeout = 5
        connection.response_body_encoding = true
      end
    end

    def stop_server
      if @pid
        begin
          Process.kill("TERM", @pid)
          Timeout.timeout(5) { Process.wait(@pid) }
        rescue Timeout::Error
          Process.kill("KILL", @pid)
          Process.wait(@pid)
        rescue Errno::ESRCH, Errno::ECHILD
          # Puma has already stopped.
        end
        @pid = nil
      end
      FileUtils.remove_entry(@directory) if @directory && File.directory?(@directory)
    end
  end

  Minitest.after_run { stop_server }

  def setup
    self.class.start_server
    @cookies = {}
  end

  def test_full_sign_in_as_alice
    page = get_home
    cookie = session_cookie(page)
    assert_match(/; path=#{Regexp.escape(BASE)}(?:;|$)/i, cookie)
    assert_match(/; secure(?:;|$)/i, cookie)
    assert_match(/; httponly(?:;|$)/i, cookie)
    assert_match(/; samesite=lax(?:;|$)/i, cookie)

    callback = choose_alice(start_sign_in(page))
    response = request(Net::HTTP::Get, callback)
    assert_redirect "#{BASE}/", response
    assert_includes get_home.body, "alice@lab.test"

    user = me.fetch("user")
    assert_equal({ "email" => "alice@lab.test", "name" => "Alice" }, user.slice("email", "name"))
    assert_match(/\A[0-9a-f-]+\z/, user.fetch("id"))
    persisted = JSON.parse(File.read(File.join(self.class.directory, "users.json")))
    assert_equal user, persisted.fetch(alice_subject)

    second_callback = choose_alice(start_sign_in(get_home))
    assert_redirect "#{BASE}/", request(Net::HTTP::Get, second_callback)
    assert_equal user, me.fetch("user")
  end

  def test_get_on_request_path_is_rejected
    response = request(Net::HTTP::Get, AUTH)
    assert_equal "405", response.code
    assert_equal "POST", response["allow"]
    assert_nil response["location"]
  end

  def test_request_post_requires_authenticity_token
    get_home
    response = request(Net::HTTP::Post, AUTH, form: {})
    assert_redirect "#{BASE}/?error=authenticity_error&strategy=google_oauth2", response
    assert_equal false, me.fetch("signed_in")
  end

  def test_callback_with_mismatched_state_fails
    callback = URI(choose_alice(start_sign_in(get_home)))
    callback.query = URI.encode_www_form(query(callback).merge("state" => "different-state"))
    response = request(Net::HTTP::Get, callback)
    assert_redirect "#{BASE}/?error=csrf_detected&strategy=google_oauth2", response
    assert_equal false, me.fetch("signed_in")
  end

  def test_authorization_code_can_only_be_exchanged_once
    code = query(choose_alice(start_sign_in(get_home))).fetch("code")
    client = JSON.parse(File.read(File.join(self.class.directory, "client.json")))
    credentials = "Basic #{Base64.strict_encode64(client.values_at("client_id", "client_secret").join(":"))}"
    grant = { grant_type: "authorization_code", code: code, redirect_uri: CALLBACK }

    no_client = request(Net::HTTP::Post, "#{IDP}/token", form: grant)
    assert_equal "401", no_client.code
    assert_equal "invalid_client", JSON.parse(no_client.body).fetch("error")
    wrong_redirect = request(Net::HTTP::Post, "#{IDP}/token", form: grant.merge(redirect_uri: "#{CALLBACK}/"),
                             authorization: credentials)
    assert_equal "400", wrong_redirect.code
    assert_equal "redirect_uri_mismatch", JSON.parse(wrong_redirect.body).fetch("error")

    first = request(Net::HTTP::Post, "#{IDP}/token", form: grant, authorization: credentials)
    assert_equal "200", first.code
    tokens = JSON.parse(first.body)
    assert_equal "Bearer", tokens.fetch("token_type")
    assert_equal 3600, tokens.fetch("expires_in")
    assert_equal "email profile", tokens.fetch("scope")
    assert_issued_tokens(tokens, client.fetch("client_id"))

    second = request(Net::HTTP::Post, "#{IDP}/token", form: grant, authorization: credentials)
    assert_equal "400", second.code
    assert_equal "invalid_grant", JSON.parse(second.body).fetch("error")
  end

  def test_me_reflects_sign_in_and_sign_out
    assert_equal({ "signed_in" => false, "user" => nil }, me)
    callback = choose_alice(start_sign_in(get_home))
    assert_redirect "#{BASE}/", request(Net::HTTP::Get, callback)
    assert_equal true, me.fetch("signed_in")

    rejected = request(Net::HTTP::Post, "#{BASE}/signout", form: {})
    assert_equal "403", rejected.code
    assert_equal true, me.fetch("signed_in")

    token = form_token(get_home.body, "#{BASE}/signout")
    signed_out = request(Net::HTTP::Post, "#{BASE}/signout", form: { authenticity_token: token })
    assert_includes %w[302 303], signed_out.code
    assert_equal "#{BASE}/", signed_out["location"]
    assert_equal({ "signed_in" => false, "user" => nil }, me)
  end

  def test_marketing_page_links_to_signin_and_displays_errors
    message = "Sign-in details <&>"
    response = request(Net::HTTP::Get, "#{BASE}/?#{URI.encode_www_form(error: message)}")
    assert_equal "200", response.code
    assert_includes response.body, LAB_NOTICE
    assert_includes response.body, 'href="#product"'
    assert_includes response.body, 'id="pricing"'
    assert_includes response.body, %(<a href="#{BASE}/signin">Sign in</a>)
    assert_includes response.body, "Sign-in details &lt;&amp;&gt;"
    refute_includes response.body, message
  end

  def test_signin_page_starts_the_existing_flow
    response = request(Net::HTTP::Get, "#{BASE}/signin?error=try_again")
    assert_equal "200", response.code
    assert_includes response.body, LAB_NOTICE
    assert_includes response.body, "<title>Lumora — Sign in</title>"
    assert_includes response.body, "Continue with Keystone ID"
    assert_includes response.body, "<fieldset disabled"
    assert_includes response.body, "Email sign-in is turned off in this lab"
    assert_includes response.body, "<code>try_again</code>"
    callback = choose_alice(start_sign_in(response))
    assert_redirect "#{BASE}/", request(Net::HTTP::Get, callback)
  end

  def test_signed_in_home_displays_dashboard
    callback = choose_alice(start_sign_in(get_home))
    assert_redirect "#{BASE}/", request(Net::HTTP::Get, callback)
    dashboard = get_home.body
    assert_includes dashboard, LAB_NOTICE
    assert_includes dashboard, "Welcome back, Alice."
    assert_includes dashboard, "Recent boards"
    assert_includes dashboard, "Workspace activity"
    assert_includes dashboard, %(<a href="#{BASE}/account">Account</a>)
    form_token(dashboard, "#{BASE}/signout")
  end

  def test_account_requires_signin_and_reads_the_connected_profile
    assert_redirect "#{BASE}/signin", request(Net::HTTP::Get, "#{BASE}/account")
    callback = choose_alice(start_sign_in(get_home))
    assert_redirect "#{BASE}/", request(Net::HTTP::Get, callback)
    response = request(Net::HTTP::Get, "#{BASE}/account")
    assert_equal "200", response.code
    refute_includes response.body, 'name="authenticity_token"'
    assert_includes response.body, LAB_NOTICE
    assert_includes response.body, "<title>Lumora — Account settings</title>"
    assert_includes response.body, "alice@lab.test"
    assert_includes response.body, "<code>#{alice_subject}</code>"
    assert_includes response.body, "This session"
    assert_includes response.body, "Current session"
    assert_includes response.body, "disabled>Delete account"
  end

  def test_keystone_chooser_displays_requested_scopes
    authorize_url = start_sign_in(get_home)
    authorize_url.query = URI.encode_www_form(query(authorize_url).merge("scope" => "email profile review<&>"))
    response = request(Net::HTTP::Get, authorize_url)
    assert_equal "200", response.code
    assert_includes response.body, LAB_NOTICE
    assert_includes response.body, "<title>Keystone ID — Choose an account</title>"
    assert_includes response.body, "to continue to <strong>Lumora</strong>"
    assert_includes response.body, "Use another account"
    assert_includes response.body, "<code>email</code>"
    assert_includes response.body, "<code>review&lt;&amp;&gt;</code>"
    refute_includes response.body, "review<&>"
  end

  def test_keystone_error_keeps_html_and_json_responses
    path = "#{IDP}/o/oauth2/auth"
    html = request(Net::HTTP::Get, path, accept: "text/html")
    assert_equal "400", html.code
    assert_includes html.body, LAB_NOTICE
    assert_includes html.body, "<title>Keystone ID — Authorization error</title>"
    assert_includes html.body, "<code>invalid_client</code>"

    json = request(Net::HTTP::Get, path, accept: "application/json")
    assert_equal "400", json.code
    assert_equal '{"error":"invalid_client"}', json.body
  end

  def test_graphql_current_user_and_deterministic_workspace
    query = <<~GRAPHQL
      query DashboardQuery {
        currentUser {
          id slug name email signInProvider
          workspace { id name plan membersCount }
          boards { id slug title updatedAt assetsCount coverHue }
          activity { id actorName verb boardTitle at }
          firstBoard: boards(first: 1) { id }
          noActivity: activity(first: 0) { id }
        }
      }
    GRAPHQL
    assert_equal({ "data" => { "currentUser" => nil } }, graphql(query, operation_name: "DashboardQuery"))

    sign_in
    result = graphql(query, operation_name: "DashboardQuery")
    profile = result.fetch("data").fetch("currentUser")
    assert_equal ["User:#{me.fetch('user').fetch('id')}", "alice", "Alice", "alice@lab.test", "keystone_id"],
                 profile.values_at("id", "slug", "name", "email", "signInProvider")
    assert_equal %w[id membersCount name plan], profile.fetch("workspace").keys.sort
    boards = profile.fetch("boards")
    assert_equal 3, boards.size
    assert_equal %w[assetsCount coverHue id slug title updatedAt], boards.first.keys.sort
    assert_equal [{ "id" => boards.first.fetch("id") }], profile.fetch("firstBoard")
    activity = profile.fetch("activity")
    assert_equal boards.map { |board| board.fetch("title") }, activity.map { |item| item.fetch("boardTitle") }
    assert_equal %w[actorName at boardTitle id verb], activity.first.keys.sort
    assert_empty profile.fetch("noActivity")

    dashboard = get_home.body
    assert_includes dashboard, "/assets/workspace.js"
    assert_includes dashboard, boards.first.fetch("title")
    assert_includes dashboard, activity.first.fetch("actorName")
    sign_in
    assert_equal result, graphql(query, operation_name: "DashboardQuery")
  end

  def test_graphql_protected_fields_require_a_session
    assert_equal "UNAUTHENTICATED", graphql_error(graphql('{ board(slug: "example") { title } }'))
    assert_equal "UNAUTHENTICATED", graphql_error(update_profile("Anonymous"))
    assert_equal "UNAUTHENTICATED", graphql_error(graphql("mutation SignOut { signOut { success } }"))
  end

  def test_graphql_mutations_without_a_matching_csrf_header_see_an_empty_session
    sign_in
    account = request(Net::HTTP::Get, "#{BASE}/account")
    assert_includes account.body, "<fieldset disabled"
    assert_includes account.body, "Enable JavaScript to edit your display name."
    before = File.read(File.join(self.class.directory, "users.json"))
    [nil, "incorrect", form_token(get_home.body, "#{BASE}/signout")].each do |token|
      assert_equal "UNAUTHENTICATED", graphql_error(update_profile("Rejected", token: token))
      refute session_cookie(@last_graphql_response)
      assert_equal "UNAUTHENTICATED", graphql_error(graphql("mutation SignOut { signOut { success } }", token: token))
      refute session_cookie(@last_graphql_response)
    end
    wrong_origin = request(Net::HTTP::Post, GRAPHQL, headers: { "Content-Type" => "application/json",
                                                              "Origin" => "https://other.test" },
                           body: JSON.generate(query: "mutation SignOut { signOut { success } }"))
    assert_equal "UNAUTHENTICATED", graphql_error(JSON.parse(wrong_origin.body))
    refute session_cookie(wrong_origin)
    assert_equal before, File.read(File.join(self.class.directory, "users.json"))
    assert_equal true, me.fetch("signed_in")

    document = "#{PROFILE_UPDATE}\nquery AccountQuery { currentUser { name } }"
    assert_equal({ "data" => { "currentUser" => { "name" => "Alice" } } }, graphql(document, operation_name: "AccountQuery"))
  end

  def test_graphql_update_profile_persists_the_trimmed_name
    sign_in("bob@lab.test")
    account = request(Net::HTTP::Get, "#{BASE}/account")
    result = update_profile(" \u00a0Bobby <Studio>\t ", token: graphql_token(account.body))
    payload = result.fetch("data").fetch("updateProfile")
    assert_empty payload.fetch("errors")
    assert_equal "Bobby <Studio>", payload.fetch("currentUser").fetch("name")
    users = JSON.parse(File.read(File.join(self.class.directory, "users.json")))
    assert_equal "Bobby <Studio>", users.values.find { |user| user["email"] == "bob@lab.test" }.fetch("name")

    sign_in("bob@lab.test")
    assert_equal "Bobby <Studio>", me.fetch("user").fetch("name")
    account = request(Net::HTTP::Get, "#{BASE}/account")
    assert_includes account.body, "Bobby &lt;Studio&gt;"
    refute_includes account.body, "Bobby <Studio>"
  end

  def test_graphql_rejects_invalid_display_names_without_saving
    sign_in
    token = graphql_token(get_home.body)
    ["", "\t\u00a0", "a" * 61].each do |name|
      payload = update_profile(name, token: token).fetch("data").fetch("updateProfile")
      assert_nil payload.fetch("currentUser")
      errors = payload.fetch("errors")
      assert_equal 1, errors.size
      error = errors.first
      assert_equal %w[input name], error.fetch("path")
      assert_match(/1 to 60/, error.fetch("message"))
    end
    assert_equal "Alice", me.fetch("user").fetch("name")
  end

  def test_graphql_sign_out_clears_the_existing_session
    sign_in
    result = graphql("mutation SignOut { signOut { success } }", token: graphql_token(get_home.body), operation_name: "SignOut")
    assert_equal({ "data" => { "signOut" => { "success" => true } } }, result)
    assert_equal({ "signed_in" => false, "user" => nil }, me)
  end

  def test_graphql_board_is_scoped_to_the_current_workspace
    sign_in("bob@lab.test")
    board = graphql("{ currentUser { boards(first: 1) { id slug } } }").dig("data", "currentUser", "boards", 0)
    query = "query BoardBySlug($slug: String!) { board(slug: $slug) { id slug } }"
    assert_equal({ "data" => { "board" => board } }, graphql(query, variables: { slug: board.fetch("slug") }))

    @cookies.clear
    sign_in
    assert_equal({ "data" => { "board" => nil } }, graphql(query, variables: { slug: board.fetch("slug") }))
  end

  def test_graphql_enforces_depth_and_complexity_limits
    depth_query = ->(levels) { '{ __type(name: "UserError") { fields { type ' + '{ ofType ' * levels + '{ name }' + ' }' * (levels + 3) }
    assert graphql(depth_query.call(6)).key?("data")
    assert_match(/depth of 11.*max depth of 10/, graphql(depth_query.call(7)).fetch("errors").first.fetch("message"))

    complexity_query = ->(count) { "{ #{(1..count).map { |index| "u#{index}: currentUser { id }" }.join(' ')} }" }
    assert graphql(complexity_query.call(100)).key?("data")
    assert_match(/complexity of 202.*max complexity of 200/, graphql(complexity_query.call(101)).fetch("errors").first.fetch("message"))
  end

  def test_graphql_rejects_oversized_and_malformed_requests
    headers = { "Content-Type" => "application/json" }
    full = JSON.generate(query: "{ currentUser { id } }").ljust(16 * 1024)
    assert_equal "200", request(Net::HTTP::Post, GRAPHQL, headers: headers, body: full).code
    assert_equal "413", request(Net::HTTP::Post, GRAPHQL, headers: headers, body: full + " ").code
    chunked = headers.merge("Transfer-Encoding" => "chunked")
    assert_equal "413", request(Net::HTTP::Post, GRAPHQL, headers: chunked, body: StringIO.new(full + " ")).code
    assert_equal "400", request(Net::HTTP::Post, GRAPHQL, headers: headers, body: "{").code
    assert_equal "400", request(Net::HTTP::Post, GRAPHQL, headers: headers, body: "[]").code
  end

  def test_graphql_get_schema_and_introspection
    response = request(Net::HTTP::Get, GRAPHQL)
    assert_equal "405", response.code
    assert_equal "POST", response["allow"]
    response = request(Net::HTTP::Get, "#{GRAPHQL}/schema")
    assert_equal "200", response.code
    assert_equal "text/plain", response.content_type
    assert_includes response.body, "updateProfile(input: UpdateProfileInput!): UpdateProfilePayload!"
    assert_includes response.body, "boards(first: Int = 10): [Board!]!"
    assert_includes response.body, "path: [String!]"
    assert_includes response.body, "signInWithOauth(input: signInWithOAuthInput!): SignInWithOAuthMutationPayload!"
    assert_includes response.body, "idToken: String!"
    assert_includes response.body, "platform: Platform"
    assert_includes response.body, "provider: OAuthProvider!"
    types = graphql("{ __schema { queryType { name } mutationType { name } } }").dig("data", "__schema")
    assert_equal({ "queryType" => { "name" => "Query" }, "mutationType" => { "name" => "Mutation" } }, types)
  end

  def test_fedcm_config_metadata_and_documentation_well_known
    config_response = request(Net::HTTP::Get, "#{FEDCM}.json")
    assert_equal "200", config_response.code
    config = JSON.parse(config_response.body)
    {
      "issue" => %w[idtoken_endpoint id_token_endpoint id_assertion_endpoint],
      "listaccounts" => %w[accounts_endpoint],
      "clientmetadata" => %w[client_metadata_endpoint client_id_metadata_endpoint],
      "signin" => %w[login_url signin_url],
      "metrics" => %w[metrics_endpoint],
      "revoke" => %w[revocation_endpoint disconnect_endpoint]
    }.each do |path, keys|
      keys.each { |key| assert_equal "#{ORIGIN}#{FEDCM}/#{path}", config.fetch(key) }
    end
    assert_equal "#15544d", config.dig("branding", "background_color")
    assert_equal [32, 40], config.dig("branding", "icons").map { |icon| icon.fetch("size") }
    assert_equal "image/svg+xml", request(Net::HTTP::Get, config.dig("branding", "icons", 0, "url")).content_type
    assert_equal({ "include" => "n" }, config.fetch("accounts"))
    assert_equal "n", config.fetch("account_label")
    assert_equal true, config.fetch("supports_add_account")
    assert_equal true, config.fetch("supports_use_other_account")
    assert_equal %w[active button passive widget], config.fetch("modes").keys.sort
    assert_equal "200", request(Net::HTTP::Get, config.fetch("login_url")).code
    metadata_uri = "#{config.fetch('client_metadata_endpoint')}?client_id=#{client_id}"
    metadata = JSON.parse(request(Net::HTTP::Get, metadata_uri, headers: FEDCM_HEADERS).body)
    assert_equal({ "privacy_policy_url" => "#{ORIGIN}#{BASE}/privacy",
                   "terms_of_service_url" => "#{ORIGIN}#{BASE}/terms" }, metadata)
    metadata.each_value { |url| assert_equal "200", request(Net::HTTP::Get, url).code }
    assert_fedcm_error request(Net::HTTP::Get, "#{FEDCM}/clientmetadata"), "400", "invalid_client"
    well_known = request(Net::HTTP::Get, "#{IDP}/.well-known/web-identity")
    assert_equal "200", well_known.code
    assert_equal({ "provider_urls" => ["#{ORIGIN}#{FEDCM}.json"], "accounts_endpoint" => config.fetch("accounts_endpoint"),
                   "login_url" => config.fetch("login_url") }, JSON.parse(well_known.body))
    assert_equal "404", request(Net::HTTP::Get, "/.well-known/web-identity").code
    client = request(Net::HTTP::Get, "#{IDP}/gsi/client")
    assert_equal "application/javascript", client.content_type
    assert_includes client.body, "navigator.credentials.get"
    assert_equal "204", request(Net::HTTP::Post, "#{FEDCM}/metrics", headers: FEDCM_HEADERS).code
  end

  def test_keystone_login_cookie_accounts_status_and_sign_out
    assert_fedcm_error request(Net::HTTP::Get, "#{FEDCM}/listaccounts"), "400", "invalid_request"
    wrong_destination = request(Net::HTTP::Get, "#{FEDCM}/listaccounts",
                                headers: { "Sec-Fetch-Site" => "cross-site", "Sec-Fetch-Dest" => "empty" })
    assert_fedcm_error wrong_destination, "400", "invalid_request"
    assert_equal [], fedcm_accounts
    status_path = "#{IDP}/gsi/status?client_id=#{client_id}"
    status = request(Net::HTTP::Get, status_path, headers: { "Origin" => ORIGIN })
    assert_cors(status)
    assert_equal({ "signed_in" => false }, JSON.parse(status.body))
    assert_equal "400", request(Net::HTTP::Get, "#{IDP}/gsi/status?client_id=unknown").code
    untrusted = request(Net::HTTP::Get, status_path, headers: { "Origin" => "https://other.test" })
    assert_fedcm_error untrusted, "403", "unauthorized_client"
    refute untrusted["access-control-allow-origin"]

    assert_equal "403", request(Net::HTTP::Post, "#{IDP}/signin", form: { account: "alice@lab.test" }).code
    idp_sign_in("bob@lab.test")
    idp_sign_in("carol@lab.test")
    idp_sign_in("bob@lab.test")
    accounts = fedcm_accounts
    assert_equal %w[bob@lab.test carol@lab.test], accounts.map { |account| account.fetch("email") }
    account = accounts.first
    assert_equal %w[approved_clients email given_name id label_hints login_hints name picture], account.keys.sort
    assert_equal ["n"], account.fetch("label_hints")
    assert_equal "Bob", account.fetch("given_name")
    assert_includes account.fetch("login_hints"), "bob@lab.test"
    assert_includes account.fetch("login_hints"), account.fetch("id")
    picture = request(Net::HTTP::Get, account.fetch("picture"))
    assert_equal "200", picture.code
    assert_equal "image/svg+xml", picture.content_type
    assert_includes picture.body, ">B</text>"
    assert_equal "404", request(Net::HTTP::Get, "#{IDP}/gsi-static/avatar/unknown.svg").code
    status = request(Net::HTTP::Get, status_path, headers: { "Origin" => ORIGIN })
    assert_cors(status)
    assert_equal({ "signed_in" => true }, JSON.parse(status.body))

    bad_cookie = @cookies.fetch("keystone.accounts") + "bad"
    tampered = request(Net::HTTP::Get, "#{FEDCM}/listaccounts",
                       headers: FEDCM_HEADERS.merge("Cookie" => "keystone.accounts=#{bad_cookie}"))
    assert_equal({ "accounts" => [] }, JSON.parse(tampered.body))
    page = request(Net::HTTP::Get, "#{IDP}/signin")
    assert_includes page.body, "Signed in to Keystone ID as Bob, Carol."
    token = form_token(page.body, "#{IDP}/signout")
    assert_equal "403", request(Net::HTTP::Post, "#{IDP}/signout", form: {}).code
    signout = request(Net::HTTP::Post, "#{IDP}/signout", form: { authenticity_token: token })
    assert_equal "303", signout.code
    assert_equal "logged-out", signout["set-login"]
    assert_match(/max-age=0/i, assert_idp_cookie(signout))
    assert_equal [], fedcm_accounts
  end

  def test_fedcm_assertion_request_validation_and_claims
    idp_sign_in("carol@lab.test")
    account = fedcm_accounts.first
    form = { client_id: client_id, account_id: account.fetch("id"), nonce: "rp-nonce",
             disclosure_text_shown: "true", is_auto_selected: "false" }
    revoked = request(Net::HTTP::Post, "#{FEDCM}/revoke", form: { client_id: client_id, account_hint: account.fetch("id") },
                      headers: FEDCM_HEADERS)
    assert_equal "200", revoked.code
    assert_cors(revoked)
    assert_empty fedcm_accounts.first.fetch("approved_clients")
    assert_fedcm_error assertion(form, headers: { "Origin" => ORIGIN }), "400", "invalid_request"
    assert_fedcm_error assertion(form.merge(client_id: "unknown")), "400", "invalid_client"
    [nil, "https://elsewhere.test", "null"].each do |origin|
      headers = FEDCM_HEADERS.dup
      origin ? headers["Origin"] = origin : headers.delete("Origin")
      other_origin = assertion(form, headers: headers)
      assert_fedcm_error other_origin, "403", "unauthorized_client"
      refute other_origin["access-control-allow-origin"]
    end
    unsigned = assertion(form.merge(account_id: alice_subject))
    assert_fedcm_error unsigned, "400", "invalid_request"
    assert_cors(unsigned)
    assert_fedcm_error assertion(form.merge("nonce[]" => "array").reject { |key, _| key == :nonce }), "400", "invalid_request"

    issued = assertion(form)
    assert_equal "200", issued.code
    assert_cors(issued)
    assert_equal [client_id], fedcm_accounts.first.fetch("approved_clients")
    jwks_response = request(Net::HTTP::Get, "#{IDP}/oauth2/v3/certs")
    jwks = JWT::JWK::Set.new(JSON.parse(jwks_response.body))
    jwt = JSON.parse(issued.body).fetch("token")
    claims, header = JWT.decode(jwt, nil, true, algorithms: ["RS256"], jwks: jwks)
    assert_equal({ "alg" => "RS256", "kid" => jwks.first.kid, "typ" => "JWT" }, header)
    assert_equal %w[aud azp email email_verified exp family_name given_name iat iss jti name nbf nonce picture sub], claims.keys.sort
    assert_equal ["https://accounts.google.com", client_id, client_id, account.fetch("id"), "carol@lab.test", true,
                  "Carol", account.fetch("picture"), "Carol", "", "rp-nonce"],
                 claims.values_at("iss", "azp", "aud", "sub", "email", "email_verified", "name", "picture", "given_name",
                                  "family_name", "nonce")
    assert_equal claims.fetch("iat"), claims.fetch("nbf")
    assert_equal 3600, claims.fetch("exp") - claims.fetch("iat")
    next_token = JSON.parse(assertion(form.reject { |key, _| key == :nonce }).body).fetch("token")
    next_claims = JWT.decode(next_token, nil, true, algorithms: ["RS256"], jwks: jwks).first
    refute_empty next_claims.fetch("nonce")
    refute_equal claims.fetch("nonce"), next_claims.fetch("nonce")
    refute_equal claims.fetch("jti"), next_claims.fetch("jti")
  end

  def test_fallback_requires_same_origin_browser_fetch
    path = "#{IDP}/gsi/fallback/listaccounts"
    assert_fedcm_error request(Net::HTTP::Get, path), "403", "invalid_request"
    assert_fedcm_error request(Net::HTTP::Get, path, headers: FALLBACK_HEADERS.merge("Sec-Fetch-Site" => "cross-site")),
                       "403", "invalid_request"
    idp_sign_in("alice@lab.test")
    response = request(Net::HTTP::Get, path, headers: FALLBACK_HEADERS)
    assert_equal "200", response.code
    assert_equal fedcm_accounts, JSON.parse(response.body).fetch("accounts")
    issue = "#{IDP}/gsi/fallback/issue"
    form = { client_id: client_id, account_id: alice_subject }
    assert_fedcm_error request(Net::HTTP::Post, issue, form: form, headers: FEDCM_HEADERS), "403", "invalid_request"
    assert_fedcm_error request(Net::HTTP::Post, issue, form: form, headers: FALLBACK_HEADERS.merge("Origin" => "https://other.test")),
                       "403", "unauthorized_client"
    response = request(Net::HTTP::Post, issue, form: form, headers: FALLBACK_HEADERS)
    assert_equal "200", response.code
    assert_cors(response)
    refute_empty JSON.parse(response.body).fetch("token")
  end

  def test_lumora_exposes_the_csrf_cookie_and_nonce_protected_consent_template
    home = get_home
    header = home["content-security-policy"]
    nonce = header[/script-src 'nonce-([^']+)'/, 1]
    refute_nil nonce
    assert_includes home.body, %(<script nonce="#{nonce}" src="#{BASE}/assets/app.js")
    assert_includes home.body, '<template id="one-tap-settings">'
    assert_includes home.body, 'data-ux_mode="popup" data-callback="handleOneTapCredential"'
    refute_includes home.body, 'data-nonce'
    assert_includes home.body, '>Agree</button>'
    csrftoken = home.get_fields("set-cookie").find { |cookie| cookie.start_with?("csrftoken=") }
    assert_match(/; path=#{Regexp.escape(BASE)}(?:;|$)/i, csrftoken)
    assert_match(/; secure(?:;|$)/i, csrftoken)
    assert_match(/; samesite=lax(?:;|$)/i, csrftoken)
    refute_match(/httponly/i, csrftoken)
    assert_equal graphql_token(home.body), URI.decode_www_form_component(@cookies.fetch("csrftoken"))
    signin = request(Net::HTTP::Get, "#{BASE}/signin")
    refute_equal header, signin["content-security-policy"]
    sign_in
    refute_includes get_home.body, 'g_id_onload'
    refute_includes request(Net::HTTP::Get, "#{BASE}/account").body, 'g_id_onload'
    refute_includes request(Net::HTTP::Get, "#{BASE}/signin").body, 'g_id_onload'
  end

  def test_persisted_graphql_transport_and_get_mutation_restriction
    manifest = persisted_manifest
    operation_files = Dir.glob(File.join(ROOT, "operations", "*.graphql"))
    assert_equal operation_files.size, manifest.size
    operation_files.each do |file|
      assert_equal "Lumora/#{Digest::SHA256.file(file).hexdigest}", manifest.fetch(File.basename(file, ".graphql"))
    end
    account = { extensions: { operationId: manifest.fetch("AccountQuery") } }
    assert_equal({ "data" => { "currentUser" => nil } }, graphql_request(account))
    sign_in
    token = graphql_token(get_home.body)
    form = { "extensions[operationId]" => manifest.fetch("UpdateProfile"),
             "variables" => JSON.generate(input: { name: "Alice" }) }
    response = request(Net::HTTP::Post, GRAPHQL, form: form, headers: { "X-CSRF-Token" => token })
    assert_equal "200", response.code, response.body
    assert_equal "Alice", JSON.parse(response.body).dig("data", "updateProfile", "currentUser", "name")
    get_vars = URI.encode_www_form(form)
    mutation = request(Net::HTTP::Get, "#{GRAPHQL}?#{get_vars}")
    assert_equal "403", mutation.code
    assert_equal "text/html", mutation.content_type
    raw_mutation = URI.encode_www_form(query: "mutation SignOut { signOut { success } }")
    assert_equal "403", request(Net::HTTP::Get, "#{GRAPHQL}?#{raw_mutation}").code
    assert_equal "403", request(Net::HTTP::Head, "#{GRAPHQL}?#{raw_mutation}").code
    assert_equal true, me.fetch("signed_in")
    get_query = URI.encode_www_form("extensions[operationId]" => manifest.fetch("AccountQuery"))
    assert_equal "Alice", JSON.parse(request(Net::HTTP::Get, "#{GRAPHQL}?#{get_query}").body).dig("data", "currentUser", "name")

    no_query = { "errors" => [{ "message" => "No query string was present" }] }
    assert_equal no_query, graphql_request({})
    assert_equal no_query, graphql_request({ query: " " })
    assert_equal no_query, graphql_request({ extensions: { operationId: "Lumora/unknown" } })
    plain = request(Net::HTTP::Post, GRAPHQL, headers: { "Content-Type" => "text/plain" }, body: JSON.generate(account))
    assert_equal "200", plain.code
    assert_equal no_query, JSON.parse(plain.body)
    assert_equal "400", request(Net::HTTP::Post, GRAPHQL, form: form.merge("variables" => "{")).code
    assert_equal({ "data" => { "currentUser" => { "name" => "Alice" } } }, graphql("{ currentUser { name } }"))
    sign_out = { operationName: "SignOut", extensions: { operationId: manifest.fetch("SignOut") } }
    unverified = request(Net::HTTP::Post, GRAPHQL, form: { "extensions[operationId]" => manifest.fetch("SignOut"),
                                                          "authenticity_token" => token })
    assert_equal "UNAUTHENTICATED", graphql_error(JSON.parse(unverified.body))
    refute session_cookie(unverified)
    assert_equal true, me.fetch("signed_in")
    assert_equal({ "data" => { "signOut" => { "success" => true } } }, graphql_request(sign_out, token: token))
    assert_equal false, me.fetch("signed_in")
  end

  def test_oauth_sign_in_uses_the_same_user_and_a_throwaway_session_without_csrf
    sign_in
    redirect_user = me.fetch("user")
    token = JSON.parse(assertion(client_id: client_id, account_id: alice_subject).body).fetch("token")
    @cookies.clear
    csrf = graphql_token(get_home.body)
    [nil, "wrong"].each do |invalid|
      payload = oauth_sign_in(token, csrf: invalid)
      assert_equal "User:#{redirect_user.fetch('id')}", payload.dig("currentUser", "id")
      assert_nil payload.fetch("otpSessionChallenge")
      assert_empty payload.fetch("errors")
      refute session_cookie(@last_graphql_response)
      assert_equal false, me.fetch("signed_in")
    end
    assert_empty oauth_sign_in(token, csrf: csrf).fetch("errors")
    assert session_cookie(@last_graphql_response)
    assert_equal redirect_user, me.fetch("user")

    idp_sign_in("carol@lab.test")
    carol = fedcm_accounts.find { |account| account["email"] == "carol@lab.test" }
    carol_jwt = JSON.parse(assertion(client_id: client_id, account_id: carol.fetch("id")).body).fetch("token")
    assert_equal "carol@lab.test", oauth_sign_in(carol_jwt).dig("currentUser", "email")
    refute session_cookie(@last_graphql_response)
    assert_equal redirect_user, me.fetch("user")
  end

  def test_oauth_sign_in_returns_the_stock_verifier_messages
    csrf = graphql_token(get_home.body)
    %w[FACEBOOK APPLE].each do |provider|
      result = oauth_sign_in("unused", csrf: csrf, provider: provider, platform: "IOS")
      assert_nil result.fetch("currentUser")
      assert_equal "UNSUPPORTED_PROVIDER", result.dig("errors", 0, "code")
    end
    key = OpenSSL::PKey::RSA.new(File.read(File.join(self.class.directory, "idp-key.pem")))
    claims = { iss: "https://accounts.google.com", aud: client_id, sub: alice_subject,
               email: "alice@lab.test", name: "Alice", exp: Time.now.to_i + 3600 }
    tests = {
      "malformed" => "Token not verified as issued by Google",
      JWT.encode(claims, OpenSSL::PKey::RSA.generate(2048), "RS256") => "Token not verified as issued by Google",
      JWT.encode(claims.merge(aud: "another-client"), key, "RS256") => "Token audience mismatch",
      JWT.encode(claims.merge(iss: "https://other.test"), key, "RS256") => "Token issuer mismatch",
      JWT.encode(claims.merge(exp: Time.now.to_i - 1), key, "RS256") => "Token signature is expired"
    }
    tests.each do |token, message|
      result = oauth_sign_in(token, csrf: csrf, platform: "ANDROID")
      assert_nil result.fetch("currentUser")
      assert_nil result.fetch("otpSessionChallenge")
      assert_equal [{ "code" => "INVALID_ID_TOKEN", "message" => "Invalid ID Token: #{message}" }], result.fetch("errors")
    end
    assert_equal false, me.fetch("signed_in")
  end

  private

  def session_cookie(response)
    response.get_fields("set-cookie").to_a.find { |cookie| cookie.start_with?("lab.session=") }
  end

  def assert_idp_cookie(response)
    cookie = response.get_fields("set-cookie").to_a.find { |entry| entry.start_with?("keystone.accounts=") }
    refute_nil cookie
    assert_match(/; path=#{Regexp.escape(IDP)}(?:;|$)/i, cookie)
    assert_match(/; secure(?:;|$)/i, cookie)
    assert_match(/; httponly(?:;|$)/i, cookie)
    assert_match(/; samesite=none(?:;|$)/i, cookie)
    cookie
  end

  def assert_cors(response)
    assert_equal ORIGIN, response["access-control-allow-origin"]
    assert_equal "true", response["access-control-allow-credentials"]
    assert_equal "Origin", response["vary"]
  end

  def assert_fedcm_error(response, status, code)
    assert_equal status, response.code, response.body
    assert_equal({ "error" => { "code" => code, "url" => "#{ORIGIN}#{IDP}/signin" } }, JSON.parse(response.body))
  end

  def client_id
    JSON.parse(File.read(File.join(self.class.directory, "client.json"))).fetch("client_id")
  end

  def idp_sign_in(email)
    path = "#{IDP}/signin"
    page = request(Net::HTTP::Get, path)
    token = form_token(page.body, path)
    response = request(Net::HTTP::Post, path, form: { account: email, authenticity_token: token })
    assert_equal "303", response.code, response.body
    assert_equal "logged-in", response["set-login"]
    assert_idp_cookie(response)
  end

  def fedcm_accounts
    response = request(Net::HTTP::Get, "#{FEDCM}/listaccounts", headers: { "Sec-Fetch-Dest" => "webidentity" })
    assert_equal "200", response.code
    JSON.parse(response.body).fetch("accounts")
  end

  def assertion(form = nil, headers: FEDCM_HEADERS, **fields)
    request(Net::HTTP::Post, "#{FEDCM}/issue", headers: headers, form: form || fields)
  end

  def persisted_manifest
    response = request(Net::HTTP::Get, "#{BASE}/persisted.json")
    assert_equal "200", response.code
    JSON.parse(response.body)
  end

  def graphql_request(payload, token: nil)
    headers = { "Content-Type" => "application/json" }
    headers["X-CSRF-Token"] = token if token
    @last_graphql_response = request(Net::HTTP::Post, GRAPHQL, headers: headers, body: JSON.generate(payload))
    assert_equal "200", @last_graphql_response.code, @last_graphql_response.body
    JSON.parse(@last_graphql_response.body)
  end

  def oauth_sign_in(token, csrf: nil, provider: "GOOGLE_OAUTH2", platform: "WEB")
    id = persisted_manifest.fetch(OAUTH_OPERATION)
    payload = { operationName: OAUTH_OPERATION, extensions: { operationId: id },
                variables: { input: { idToken: token, provider: provider, platform: platform } } }
    graphql_request(payload, token: csrf).fetch("data").fetch("signInWithOauth")
  end

  def request(method, path, form: nil, authorization: nil, accept: nil, headers: {}, body: nil)
    uri = URI.join(ORIGIN, path.to_s)
    assert_equal ORIGIN, uri.origin
    req = method.new(uri.request_uri)
    req["Host"] = uri.host
    req["X-Forwarded-Proto"] = "https"
    cookies = @cookies.reject { |name, _| name == "keystone.accounts" && !uri.path.start_with?("#{IDP}/") }
    req["Cookie"] = cookies.map { |name, value| "#{name}=#{value}" }.join("; ") unless cookies.empty?
    req["Authorization"] = authorization if authorization
    req["Accept"] = accept if accept
    headers.each { |key, value| req[key] = value }
    req.set_form_data(form) if form
    if body.respond_to?(:read)
      req.body_stream = body
    elsif body
      req.body = body
    end

    response = self.class.http.request(req)
    response.get_fields("set-cookie").to_a.each do |cookie|
      name, value = cookie.split(";", 2).first.split("=", 2)
      value.empty? ? @cookies.delete(name) : @cookies[name] = value
    end
    response
  end

  def get_home
    request(Net::HTTP::Get, "#{BASE}/").tap { |response| assert_equal "200", response.code }
  end

  def me
    response = request(Net::HTTP::Get, "#{BASE}/me")
    assert_equal "200", response.code
    JSON.parse(response.body)
  end

  def form_token(html, path)
    form = html[/<form\b[^>]*\bmethod="post" action="#{Regexp.escape(path)}"[^>]*>(.*?)<\/form>/m, 1]
    refute_nil form
    token = form[/name="authenticity_token" value="([^"]+)"/, 1]
    refute_nil token
    CGI.unescapeHTML(token)
  end

  def start_sign_in(page)
    token = form_token(page.body, AUTH)
    response = request(Net::HTTP::Post, AUTH, form: { authenticity_token: token })
    assert_equal "302", response.code
    assert_match(/\A#{Regexp.escape("#{ORIGIN}#{IDP}/o/oauth2/auth")}\?/, response.fetch("location"))
    url = URI(response.fetch("location"))
    params = query(url)
    assert_equal CALLBACK, params.fetch("redirect_uri")
    assert_equal "select_account", params.fetch("prompt")
    assert_equal "email profile", params.fetch("scope")
    assert_equal "offline", params.fetch("access_type")
    url
  end

  def choose_alice(authorize_url)
    choose_account(authorize_url, "alice@lab.test")
  end

  def choose_account(authorize_url, email)
    chooser = request(Net::HTTP::Get, authorize_url)
    assert_equal "200", chooser.code
    %w[alice bob carol].each { |name| assert_includes chooser.body, "#{name}@lab.test" }
    fields = chooser.body.scan(/type="hidden" name="([^"]+)" value="([^"]*)"/).to_h
    fields.transform_values! { |value| CGI.unescapeHTML(value) }
    choice = authorize_url.dup
    choice.query = URI.encode_www_form(fields.merge("account" => email))
    response = request(Net::HTTP::Get, choice)
    assert_equal "302", response.code
    assert_equal "logged-in", response["set-login"]
    assert_idp_cookie(response)
    callback = URI(response.fetch("location"))
    assert_equal CALLBACK, "#{callback.origin}#{callback.path}"
    assert_equal query(authorize_url).fetch("state"), query(callback).fetch("state")
    callback
  end

  def sign_in(email = "alice@lab.test")
    callback = choose_account(start_sign_in(get_home), email)
    assert_redirect "#{BASE}/", request(Net::HTTP::Get, callback)
  end

  def graphql(query, variables: nil, operation_name: nil, token: nil)
    headers = { "Content-Type" => "application/json" }
    headers["X-CSRF-Token"] = token if token
    body = JSON.generate(query: query, variables: variables, operationName: operation_name)
    response = @last_graphql_response = request(Net::HTTP::Post, GRAPHQL, headers: headers, body: body)
    assert_equal "200", response.code, response.body
    assert_equal "application/json", response.content_type
    JSON.parse(response.body)
  end

  def graphql_token(html)
    token = html[/<meta name="csrf-token" content="([^"]+)">/, 1]
    refute_nil token
    CGI.unescapeHTML(token)
  end

  def graphql_error(result)
    result.fetch("errors").first.fetch("extensions").fetch("code")
  end

  def update_profile(name, token: nil)
    graphql(PROFILE_UPDATE, variables: { input: { name: name } }, operation_name: "UpdateProfile", token: token)
  end

  def assert_redirect(location, response)
    assert_equal "302", response.code
    assert_equal location, response["location"]
  end

  def query(url)
    URI.decode_www_form(URI(url.to_s).query).to_h
  end

  def alice_subject
    accounts = JSON.parse(File.read(File.join(self.class.directory, "idp-accounts.json")))
    accounts.fetch("alice@lab.test").fetch("sub")
  end

  def assert_issued_tokens(tokens, client_id)
    access_token = tokens.fetch("access_token")
    id_token = tokens.fetch("id_token")
    certs = request(Net::HTTP::Get, "#{IDP}/oauth2/v3/certs")
    assert_equal "200", certs.code
    jwks = JWT::JWK::Set.new(JSON.parse(certs.body))
    claims, header = JWT.decode(id_token, nil, true, algorithms: ["RS256"], jwks: jwks,
                                iss: "https://accounts.google.com", verify_iss: true,
                                aud: client_id, verify_aud: true)
    assert_equal jwks.first.kid, header.fetch("kid")
    assert_equal alice_subject, claims.fetch("sub")
    assert_equal client_id, claims.fetch("azp")
    assert_equal "alice@lab.test", claims.fetch("email")
    assert_equal true, claims.fetch("email_verified")
    assert_equal "Alice", claims.fetch("name")
    assert_equal 3600, claims.fetch("exp") - claims.fetch("iat")
    digest = OpenSSL::Digest::SHA256.digest(access_token)[0, 16]
    assert_equal Base64.urlsafe_encode64(digest, padding: false), claims.fetch("at_hash")

    profile = request(Net::HTTP::Get, "#{IDP}/oauth2/v3/userinfo", authorization: "Bearer #{access_token}")
    assert_equal "200", profile.code
    assert_equal alice_subject, JSON.parse(profile.body).fetch("sub")
    tokeninfo = "#{IDP}/oauth2/v3/tokeninfo"
    get_info = request(Net::HTTP::Get, "#{tokeninfo}?#{URI.encode_www_form(id_token: id_token)}")
    post_info = request(Net::HTTP::Post, tokeninfo, form: { access_token: access_token })
    [get_info, post_info].each do |response|
      assert_equal "200", response.code
      info = JSON.parse(response.body)
      assert_equal client_id, info.fetch("aud")
      assert_equal "email profile", info.fetch("scope")
    end
  end
end
