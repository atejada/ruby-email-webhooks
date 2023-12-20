# frozen_string_literal: true

# Load gems
require 'nylas'
require 'sinatra'
require 'sinatra/config_file'

message_opened = Data.define(:id, :date, :label, :subject, :count)
messages_opened = []
link_clicked = Data.define(:id, :date, :label, :link, :count)
links_clicked = []

get '/webhook' do
  params['challenge'].to_s if params.include? 'challenge'
end

post '/webhook' do
  # We need to verify that the signature comes from Nylas
  is_genuine = verify_signature(request.body.read, ENV['CLIENT_SECRET'],
                                request.env['HTTP_X_NYLAS_SIGNATURE'])
  unless is_genuine
    status 401
    'Signature verification failed!'
  end

  # Initialize Nylas client
  nylas = Nylas::Client.new(
    api_key: ENV['V3_TOKEN']
  )

  # We read the webhook information and store it on the data class
  request.body.rewind
  model = JSON.parse(request.body.read)
  case model['type']
      when "message.opened"
              message, _ = nylas.messages.find(identifier: ENV['GRANT_ID'], message_id: model['data']['object']['message_id'])
              message_hook = message_opened.new(model['id'], Time.at(message[:date]).strftime("%d/%m/%Y at %H:%M:%S"), 
                                                                            model['data']['object']['label'], message[:subject], 
                                                                            model['data']['object']['message_data']['count'])
              messages_opened.append(message_hook)
      when "message.link_clicked"
               link_hook = link_clicked.new(model['id'], Time.at(message[:date]).strftime("%d/%m/%Y at %H:%M:%S"), 
                                                        model['data']['object']['label'],model['data']['object']['link_data']['url'],
                                                        model['data']['object']['link_data']['count'])
              links_clicked.append(link_hook)
  end

  status 200
  'Webhook received'
end

get '/' do
  erb :main, locals: { messages_opened: messages_opened, links_clicked: links_clicked }
end

# We generate a signature with our client secret and compare it with the one from Nylas
def verify_signature(message, key, signature)
  digest = OpenSSL::Digest.new('sha256')
  digest = OpenSSL::HMAC.hexdigest(digest, key, message)
  secure_compare(digest, signature)
end

# We compare the keys to see if they are the same
def secure_compare(a_key, b_key)
  return false if a_key.empty? || b_key.empty? || a_key.bytesize != b_key.bytesize

  l = a_key.unpack "C#{a_key.bytesize}"

  res = 0
  b_key.each_byte { |byte| res |= byte ^ l.shift }
  res.zero?
end
