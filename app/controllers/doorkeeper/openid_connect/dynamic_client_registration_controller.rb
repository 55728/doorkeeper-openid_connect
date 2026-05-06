# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    class DynamicClientRegistrationController < ::Doorkeeper::ApplicationMetalController
      def register
        registration = OAuth::DynamicRegistrationRequest.new(::Doorkeeper.configuration, params)

        unless registration.valid?
          render json: registration.error_response, status: :bad_request
          return
        end

        client = Doorkeeper::Application.create!(application_params(registration))
        render json: registration_response(client, registration), status: :created
      rescue ActiveRecord::RecordInvalid => e
        render json: { error: "invalid_client_params", error_description: e.record.errors.full_messages.join(", ") },
          status: :bad_request
      end

      private

      def application_params(registration)
        {
          name: params.dig(:client_name),
          redirect_uri: params.dig(:redirect_uris) || [],
          scopes: params.dig(:scope),
          confidential: registration.confidential_client?,
        }
      end

      def registration_response(doorkeeper_application, registration)
        response = {
          client_id: doorkeeper_application.uid,
          client_id_issued_at: doorkeeper_application.created_at.to_i,
          redirect_uris: doorkeeper_application.redirect_uri.split,
          token_endpoint_auth_method: registration.token_endpoint_auth_method,
          token_endpoint_auth_methods_supported: registration.token_endpoint_auth_methods_supported,
          response_types: registration.requested_response_types,
          grant_types: registration.requested_grant_types,
          scope: doorkeeper_application.scopes.to_s,
          application_type: registration.requested_application_type,
        }

        if registration.confidential_client?
          response[:client_secret] =
            doorkeeper_application.plaintext_secret || doorkeeper_application.secret
        end

        response
      end
    end
  end
end
