# frozen_string_literal: true

#
# Ruby Text Intelligence Starter - Backend Server
#
# Simple Sinatra server providing text intelligence analysis
# powered by Deepgram's Text Intelligence service.
#
# Key Features:
# - Contract-compliant API endpoint: POST /api/text-intelligence
# - Accepts text or URL in JSON body
# - Supports multiple intelligence features: summarization, topics, sentiment, intents
# - JWT session auth with rate limiting (production only)
# - CORS enabled for frontend communication
#

require 'sinatra'
require 'sinatra/cross_origin'
require 'json'
require 'jwt'
require 'securerandom'
require 'net/http'
require 'uri'
require 'toml-rb'
require 'dotenv/load'

# ============================================================================
# CONFIGURATION
# ============================================================================

PORT = (ENV['PORT'] || 8081).to_i
HOST = ENV['HOST'] || '0.0.0.0'

set :port, PORT
set :bind, HOST

# ============================================================================
# SESSION AUTH - JWT tokens for production security
# ============================================================================

# Session secret for signing JWTs
SESSION_SECRET = ENV['SESSION_SECRET'] || SecureRandom.hex(32)

# JWT expiry time (1 hour)
JWT_EXPIRY = 3600

# Validates JWT from Authorization header.
# Returns a 401 JSON error if the token is missing or invalid.
def require_session!
  auth_header = request.env['HTTP_AUTHORIZATION'] || ''

  unless auth_header.start_with?('Bearer ')
    halt 401, { 'Content-Type' => 'application/json' }, JSON.generate(
      error: {
        type: 'AuthenticationError',
        code: 'MISSING_TOKEN',
        message: 'Authorization header with Bearer token is required'
      }
    )
  end

  token = auth_header[7..]
  begin
    JWT.decode(token, SESSION_SECRET, true, algorithm: 'HS256')
  rescue JWT::ExpiredSignature
    halt 401, { 'Content-Type' => 'application/json' }, JSON.generate(
      error: {
        type: 'AuthenticationError',
        code: 'INVALID_TOKEN',
        message: 'Session expired, please refresh the page'
      }
    )
  rescue JWT::DecodeError
    halt 401, { 'Content-Type' => 'application/json' }, JSON.generate(
      error: {
        type: 'AuthenticationError',
        code: 'INVALID_TOKEN',
        message: 'Invalid session token'
      }
    )
  end
end

# ============================================================================
# API KEY LOADING
# ============================================================================

# Loads the Deepgram API key from environment variables
def load_api_key
  api_key = ENV['DEEPGRAM_API_KEY']

  unless api_key && !api_key.empty?
    warn "\n\u274C ERROR: Deepgram API key not found!\n"
    warn "Please set your API key using one of these methods:\n"
    warn "1. Create a .env file (recommended):"
    warn "   DEEPGRAM_API_KEY=your_api_key_here\n"
    warn "2. Environment variable:"
    warn "   export DEEPGRAM_API_KEY=your_api_key_here\n"
    warn "Get your API key at: https://console.deepgram.com\n"
    exit 1
  end

  api_key
end

DEEPGRAM_API_KEY = load_api_key

# Deepgram Read API base URL
DEEPGRAM_READ_URL = 'https://api.deepgram.com/v1/read'

# ============================================================================
# SETUP - CORS middleware
# ============================================================================

configure do
  enable :cross_origin
end

before do
  response.headers['Access-Control-Allow-Origin'] = '*'
end

options '*' do
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
  200
end

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Validates that JSON body has exactly one of text or url
#
# @param body [Hash] Parsed JSON body
# @return [Array(Hash, String)] Tuple of (source_hash, error_message)
#   source_hash is nil if validation fails
def validate_text_input(body)
  text = body['text']
  url = body['url']

  if (!text || text.empty?) && (!url || url.empty?)
    return [nil, "Request must contain either 'text' or 'url' field"]
  end

  if text && !text.empty? && url && !url.empty?
    return [nil, "Request must contain either 'text' or 'url', not both"]
  end

  if url && !url.empty?
    unless url.start_with?('http://', 'https://')
      return [nil, 'Invalid URL format']
    end
    return [{ 'url' => url }, nil]
  end

  if text.strip.empty?
    return [nil, 'Text content cannot be empty']
  end

  [{ 'text' => text }, nil]
end

# Converts query parameters to Deepgram API options
#
# @param params [Hash] Sinatra params hash
# @return [Array(Hash, String)] Tuple of (options_hash, error_message)
def build_deepgram_options(params)
  options = {
    'language' => params['language'] || 'en'
  }

  # Handle summarize parameter (can be 'true', 'v2')
  summarize = params['summarize']
  if summarize == 'true'
    options['summarize'] = 'true'
  elsif summarize == 'v2'
    options['summarize'] = 'v2'
  elsif summarize == 'v1'
    return [nil, 'Summarization v1 is no longer supported. Please use v2 or true.']
  end

  # Boolean features
  options['topics'] = 'true' if params['topics'] == 'true'
  options['sentiment'] = 'true' if params['sentiment'] == 'true'
  options['intents'] = 'true' if params['intents'] == 'true'

  [options, nil]
end

# Formats error responses in a consistent structure per the contract
#
# @param error_type [String] "validation_error" or "processing_error"
# @param code [String] Error code string
# @param message [String] Human-readable error message
# @return [String] JSON string of formatted error response
def format_error_response(error_type, code, message)
  JSON.generate(
    error: {
      type: error_type,
      code: code,
      message: message,
      details: {}
    }
  )
end

# Calls the Deepgram Read API with the given source and options
#
# @param source [Hash] Either { 'text' => '...' } or { 'url' => '...' }
# @param options [Hash] Query parameters for the API
# @return [Hash] Parsed JSON response from Deepgram
def call_deepgram_api(source, options)
  uri = URI.parse(DEEPGRAM_READ_URL)
  uri.query = URI.encode_www_form(options)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Post.new(uri.request_uri)
  request['Authorization'] = "Token #{DEEPGRAM_API_KEY}"
  request['Content-Type'] = 'application/json'
  request.body = JSON.generate(source)

  response = http.request(request)

  unless response.is_a?(Net::HTTPSuccess)
    error_body = begin
      JSON.parse(response.body)
    rescue StandardError
      { 'err_msg' => response.body }
    end
    raise "Deepgram API error (#{response.code}): #{error_body['err_msg'] || response.body}"
  end

  JSON.parse(response.body)
end

# ============================================================================
# SESSION ROUTES - Auth endpoints (unprotected)
# ============================================================================

# GET /api/session - Issues a signed JWT for session authentication
get '/api/session' do
  content_type :json

  payload = {
    iat: Time.now.to_i,
    exp: Time.now.to_i + JWT_EXPIRY
  }
  token = JWT.encode(payload, SESSION_SECRET, 'HS256')

  JSON.generate(token: token)
end

# ============================================================================
# API ROUTES
# ============================================================================

# POST /api/text-intelligence
#
# Contract-compliant text intelligence endpoint.
# Accepts:
# - Query parameters: summarize, topics, sentiment, intents, language (all optional)
# - Body: JSON with either text or url field (required, not both)
#
# Returns:
# - Success (200): JSON with results object containing requested intelligence features
# - Error (4XX): JSON error response matching contract format
post '/api/text-intelligence' do
  content_type :json
  require_session!

  begin
    # Parse JSON body
    body = begin
      JSON.parse(request.body.read)
    rescue JSON::ParserError
      halt 400, format_error_response('validation_error', 'INVALID_TEXT', 'Request body must be valid JSON')
    end

    # Validate text input
    source, error_msg = validate_text_input(body)
    if error_msg
      code = error_msg.downcase.include?('url') ? 'INVALID_URL' : 'INVALID_TEXT'
      halt 400, format_error_response('validation_error', code, error_msg)
    end

    # Build Deepgram options from query parameters
    options, error_msg = build_deepgram_options(params)
    if error_msg
      halt 400, format_error_response('validation_error', 'INVALID_TEXT', error_msg)
    end

    # Call Deepgram Read API
    response_data = call_deepgram_api(source, options)

    # Return results
    JSON.generate(results: response_data['results'] || {})

  rescue StandardError => e
    warn "Text Intelligence Error: #{e.message}"
    warn e.backtrace&.first(5)&.join("\n")

    error_code = 'INVALID_TEXT'
    status_code = 500

    if e.message.downcase.include?('text')
      error_code = 'INVALID_TEXT'
      status_code = 400
    elsif e.message.downcase.include?('url')
      error_code = 'INVALID_URL'
      status_code = 400
    elsif e.message.downcase.include?('too long')
      error_code = 'TEXT_TOO_LONG'
      status_code = 400
    end

    message = status_code == 400 ? e.message : 'Text processing failed'
    halt status_code, format_error_response('processing_error', error_code, message)
  end
end

# GET /health - Health check endpoint
get '/health' do
  content_type :json
  JSON.generate(status: 'ok', service: 'text-intelligence')
end

# GET /api/metadata - Returns metadata from deepgram.toml
get '/api/metadata' do
  content_type :json

  begin
    config = TomlRB.load_file('deepgram.toml')

    unless config['meta']
      halt 500, JSON.generate(
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Missing [meta] section in deepgram.toml'
      )
    end

    JSON.generate(config['meta'])

  rescue Errno::ENOENT
    halt 500, JSON.generate(
      error: 'INTERNAL_SERVER_ERROR',
      message: 'deepgram.toml file not found'
    )
  rescue StandardError => e
    warn "Error reading metadata: #{e.message}"
    halt 500, JSON.generate(
      error: 'INTERNAL_SERVER_ERROR',
      message: "Failed to read metadata from deepgram.toml: #{e.message}"
    )
  end
end

# ============================================================================
# SERVER START
# ============================================================================

puts ''
puts '=' * 70
puts "Ruby Text Intelligence Server (Backend API)"
puts '=' * 70
puts "Backend API Server running at http://localhost:#{PORT}"
puts ''
puts 'GET  /api/session'
puts 'POST /api/text-intelligence (auth required)'
puts 'GET  /api/metadata'
puts 'GET  /health'
puts '=' * 70
puts ''
