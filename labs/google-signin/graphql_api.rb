# frozen_string_literal: true

require "digest"
require "graphql"
require "google-id-token"
require "json"
require_relative "workspace_data"

module Lab
  module GraphQLAPI
    PATH = "/graphql"
    MAX_BODY_BYTES = 16 * 1024

    class AuthenticityToken < Rack::Protection::AuthenticityToken
      def accepts?(env)
        # GraphQL applies null-session semantics after selecting the operation.
        return true if env["REQUEST_METHOD"] == "POST" && env["PATH_INFO"] == PATH

        super
      end
    end

    HEADER_VALIDATOR = Rack::Protection::AuthenticityToken.new(nil, authenticity_param: nil)

    def self.require_user(context)
      context[:user] || raise(GraphQL::ExecutionError.new("Sign in to continue.", extensions: { code: "UNAUTHENTICATED" }))
    end

    class Workspace < GraphQL::Schema::Object
      field :id, ID, null: false
      field :name, String, null: false
      field :plan, String, null: false
      field :members_count, Integer, null: false
    end

    class Board < GraphQL::Schema::Object
      field :id, ID, null: false
      field :slug, String, null: false
      field :title, String, null: false
      field :updated_at, String, null: false
      field :assets_count, Integer, null: false
      field :cover_hue, Integer, null: false
    end

    class Activity < GraphQL::Schema::Object
      field :id, ID, null: false
      field :actor_name, String, null: false
      field :verb, String, null: false
      field :board_title, String, null: false
      field :at, String, null: false
    end

    class CurrentUser < GraphQL::Schema::Object
      field :id, ID, null: false
      field :slug, String, null: false
      field :name, String, null: false
      field :email, String, null: false
      field :sign_in_provider, String, null: false
      field :workspace, Workspace, null: false
      field :boards, [Board], null: false do
        argument :first, Integer, required: false, default_value: 10
      end
      field :activity, [Activity], null: false do
        argument :first, Integer, required: false, default_value: 10
      end
    end

    class Query < GraphQL::Schema::Object
      field :current_user, CurrentUser
      field :board, Board do
        argument :slug, String, required: true
      end

      def current_user
        context[:user]
      end

      def board(slug:)
        GraphQLAPI.require_user(context).boards.find { |board| board.fetch(:slug) == slug }
      end
    end

    class UserError < GraphQL::Schema::Object
      field :code, String, null: false
      field :path, [String]
      field :message, String, null: false
    end

    class UpdateProfileInput < GraphQL::Schema::InputObject
      argument :name, String, required: true
    end

    class SessionMutation < GraphQL::Schema::Mutation
      null false

      def ready?(**)
        GraphQLAPI.require_user(context)
        true
      end
    end

    class UpdateProfile < SessionMutation
      argument :input, UpdateProfileInput, required: true
      field :current_user, CurrentUser
      field :errors, [UserError], null: false

      def resolve(input:)
        name = input.name.gsub(/\A[[:space:]]+|[[:space:]]+\z/, "")
        unless (1..60).cover?(name.length)
          return { errors: [{ code: "INVALID_NAME", path: %w[input name], message: "Display name must be 1 to 60 characters." }] }
        end

        user = context[:update_name].call(name)
        context[:user] = user && WorkspaceData.new(user)
        { current_user: GraphQLAPI.require_user(context), errors: [] }
      end
    end

    class SignOut < SessionMutation
      field :success, Boolean, null: false

      def resolve
        context[:sign_out].call
        context[:user] = nil
        { success: true }
      end
    end

    class OAuthProvider < GraphQL::Schema::Enum
      value "GOOGLE_OAUTH2"
      value "FACEBOOK"
      value "APPLE"
    end

    class Platform < GraphQL::Schema::Enum
      value "WEB"
      value "IOS"
      value "ANDROID"
    end

    class SignInWithOAuthInput < GraphQL::Schema::InputObject
      graphql_name "signInWithOAuthInput"
      argument :id_token, String, required: true
      argument :provider, OAuthProvider, required: true
      argument :platform, Platform, required: false
    end

    class SignInWithOAuth < GraphQL::Schema::Mutation
      graphql_name "SignInWithOAuthMutation"
      null false
      argument :input, SignInWithOAuthInput, required: true
      field :current_user, CurrentUser
      field :otp_session_challenge, String
      field :errors, [UserError], null: false

      def resolve(input:)
        if input.provider != "GOOGLE_OAUTH2"
          return { errors: [{ code: "UNSUPPORTED_PROVIDER", message: "This sign-in provider is unavailable." }] }
        end

        user = context[:oauth_sign_in].call(input.id_token)
        context[:user] = WorkspaceData.new(user)
        { current_user: context[:user], errors: [] }
      rescue GoogleIDToken::ValidationError, GoogleIDToken::CertificateError => error
        { errors: [{ code: "INVALID_ID_TOKEN", message: "Invalid ID Token: #{error.message}" }] }
      end
    end

    class Mutation < GraphQL::Schema::Object
      field :update_profile, mutation: UpdateProfile
      field :sign_out, mutation: SignOut
      field :sign_in_with_oauth, mutation: SignInWithOAuth
    end

    class Schema < GraphQL::Schema
      query Query
      mutation Mutation
      max_depth 10
      max_complexity 200
      complexity_cost_calculation_mode :future
    end

    SDL = Schema.to_definition.freeze

    OPERATIONS = Dir.glob(File.join(__dir__, "operations", "*.graphql")).to_h do |file|
      query = File.read(file)
      name = File.basename(file, ".graphql")
      [name, { "id" => "Lumora/#{Digest::SHA256.hexdigest(query)}", "query" => query }]
    end.freeze
    PERSISTED_QUERIES = OPERATIONS.values.to_h { |entry| entry.values_at("id", "query") }.freeze
    MANIFEST = JSON.generate(OPERATIONS.transform_values { |entry| entry.fetch("id") }).freeze
  end
end
