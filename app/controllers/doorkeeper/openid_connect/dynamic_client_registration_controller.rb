# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    class DynamicClientRegistrationController < ::Doorkeeper::ApplicationMetalController
      include GrantTypesSupportedMixin
      include TokenEndpointAuthMethodsSupportedMixin

      DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_basic"
      PUBLIC_CLIENT_AUTH_METHOD = "none"

      def register
        unless supported_auth_methods.include?(requested_auth_method)
          render json: {
            error: "invalid_client_metadata",
            error_description: "token_endpoint_auth_method '#{requested_auth_method}' is not supported. " \
                               "Supported methods: #{supported_auth_methods.join(", ")}",
          }, status: :bad_request
          return
        end

        client = Doorkeeper::Application.create!(application_params)
        render json: registration_response(client), status: :created
      rescue ActiveRecord::RecordInvalid => e
        render json: { error: "invalid_client_params", error_description: e.record.errors.full_messages.join(", ") },
          status: :bad_request
      end

      private

      def application_params
        {
          name: params.dig(:client_name),
          redirect_uri: params.dig(:redirect_uris) || [],
          scopes: params.dig(:scope),
          confidential: confidential_client?,
        }
      end

      def requested_auth_method
        params[:token_endpoint_auth_method].presence || DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD
      end

      def confidential_client?
        requested_auth_method != PUBLIC_CLIENT_AUTH_METHOD
      end

      def supported_auth_methods
        token_endpoint_auth_methods_supported + [PUBLIC_CLIENT_AUTH_METHOD]
      end

      def registration_response(doorkeeper_application)
        doorkeeper_config = ::Doorkeeper.configuration

        response = {
          client_id: doorkeeper_application.uid,
          client_id_issued_at: doorkeeper_application.created_at.to_i,
          redirect_uris: doorkeeper_application.redirect_uri.split,
          token_endpoint_auth_method: requested_auth_method,
          token_endpoint_auth_methods_supported: token_endpoint_auth_methods_supported,
          response_types: doorkeeper_config.authorization_response_types,
          grant_types: grant_types_supported(doorkeeper_config),
          scope: doorkeeper_application.scopes.to_s,
          application_type: "web",
        }

        if confidential_client?
          response[:client_secret] =
            doorkeeper_application.plaintext_secret || doorkeeper_application.secret
        end

        response
      end
    end
  end
end
