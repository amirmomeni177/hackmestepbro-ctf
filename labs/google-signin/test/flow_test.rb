# frozen_string_literal: true

require "base64"
require "cgi"
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
    @cookie = nil
  end

  def test_full_sign_in_as_alice
    page = get_home
    cookie = page["set-cookie"]
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

  def test_graphql_mutations_require_a_matching_csrf_header
    sign_in
    account = request(Net::HTTP::Get, "#{BASE}/account")
    assert_includes account.body, "<fieldset disabled"
    assert_includes account.body, "Enable JavaScript to edit your display name."
    before = File.read(File.join(self.class.directory, "users.json"))
    [nil, "incorrect", form_token(get_home.body, "#{BASE}/signout")].each do |token|
      assert_equal "INVALID_CSRF_TOKEN", graphql_error(update_profile("Rejected", token: token))
      assert_equal "INVALID_CSRF_TOKEN", graphql_error(graphql("mutation SignOut { signOut { success } }", token: token))
    end
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

    @cookie = nil
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
    types = graphql("{ __schema { queryType { name } mutationType { name } } }").dig("data", "__schema")
    assert_equal({ "queryType" => { "name" => "Query" }, "mutationType" => { "name" => "Mutation" } }, types)
  end

  private

  def request(method, path, form: nil, authorization: nil, accept: nil, headers: {}, body: nil)
    uri = URI.join(ORIGIN, path.to_s)
    assert_equal ORIGIN, uri.origin
    req = method.new(uri.request_uri)
    req["Host"] = uri.host
    req["X-Forwarded-Proto"] = "https"
    req["Cookie"] = @cookie if @cookie
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
    @cookie = response["set-cookie"].split(";", 2).first if response["set-cookie"]
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
    form = html[/<form method="post" action="#{Regexp.escape(path)}">(.*?)<\/form>/m, 1]
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
    response = request(Net::HTTP::Post, GRAPHQL, headers: headers, body: body)
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
