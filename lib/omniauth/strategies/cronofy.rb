module OmniAuth
  module Strategies
    class Cronofy < CronofyBase
      option :name, "cronofy"

      uid { raw_info['account_id'] }

      info do
        {
          :email => raw_info['email'],
          :name => raw_info['name']
        }
      end

      extra do
        {
          'raw_info' => raw_info,
          'linking_profile' => access_token['linking_profile'],
        }
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def raw_info
        @raw_info ||= access_token.get("#{client_options[:api_url]}/v1/account").parsed['account']
      end

      def request_phase
        link_token = session['omniauth.params']['link_token']
        provider_name = session['omniauth.params']['provider_name']
        options[:authorize_params] ||= {}
        options[:authorize_params].merge!(:avoid_linking => true)
        if link_token && !link_token.empty?
          options[:authorize_params].merge!(:link_token => link_token)
        end
        if provider_name && !provider_name.empty?
          options[:authorize_params].merge!(:provider_name => provider_name)
        end
        super
      end
    end
  end
end
