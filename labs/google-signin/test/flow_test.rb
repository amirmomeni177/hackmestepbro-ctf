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

  private

  def request(method, path, form: nil, authorization: nil)
    uri = URI.join(ORIGIN, path.to_s)
    assert_equal ORIGIN, uri.origin
    req = method.new(uri.request_uri)
    req["Host"] = uri.host
    req["X-Forwarded-Proto"] = "https"
    req["Cookie"] = @cookie if @cookie
    req["Authorization"] = authorization if authorization
    req.set_form_data(form) if form

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
    chooser = request(Net::HTTP::Get, authorize_url)
    assert_equal "200", chooser.code
    %w[alice bob carol].each { |name| assert_includes chooser.body, "#{name}@lab.test" }
    fields = chooser.body.scan(/type="hidden" name="([^"]+)" value="([^"]*)"/).to_h
    fields.transform_values! { |value| CGI.unescapeHTML(value) }
    choice = authorize_url.dup
    choice.query = URI.encode_www_form(fields.merge("account" => "alice@lab.test"))
    response = request(Net::HTTP::Get, choice)
    assert_equal "302", response.code
    callback = URI(response.fetch("location"))
    assert_equal CALLBACK, "#{callback.origin}#{callback.path}"
    assert_equal query(authorize_url).fetch("state"), query(callback).fetch("state")
    callback
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
