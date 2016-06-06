# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This filter helps parse SIP messages.
#
# For example, if you have a log message which contains a sip message in a field
#  you can parse those automatically by configuring:
# [source,ruby]
#     filter {
#       ...
#       sip { source => "k_Detail"}
#     }
#
# The above will add several new fields starting with `sip_`:
#
# * `sip_method: REGISTER`
# * `sip_request_uri: sip:rd.pexip.com`
# * `sip_cseq: 1533475445 REGISTER`
# ...
#
# You can configure the string to separate new-lines (default: `^M`) and the prefix (`sip_`)
# 
class LogStash::Filters::SIP < LogStash::Filters::Base

  config_name "sip"

  # The field to parse SIP message from
  config :source, :validate => :string, :default => "message"

  # String to split message into new-lines with
  config :line_split, :validate => :string, :default => '^M'

  # A string to prepend to all of the extracted header/values
  config :prefix, :validate => :string, :default => 'sip_'

  # An array specifying the headers/values to add to the event
  config :include_keys, :validate => :array, :default => [
           "method", "request_uri",
           "status_code", "status_reason",
           "call_id", "contact", "cseq", "from", "to", "user_agent"]

  # An array specifying the headers/values to not add to the event
  config :exclude_keys, :validate => :array, :default => []

  public
  def register
  end # def register

  def want_key(key)
    return false if not @include_keys.empty? and not @include_keys.include?(key)
    return false if @exclude_keys.include?(key)
    return true
  end

  def parse(text, fields)
    # split into header/body via two new-lines
    parts = text.split(@line_split + @line_split)    
    headers = parts[0].split(@line_split)
    # save the body if it exists
    fields['body'] = parts[1] if parts.length > 1
    # MCU sip messages are logged started with a newline
    headers.shift if headers[0] == ''

    # first line is e.g. "REGISTER sip:rd.pexip.com SIP/2.0" for a request
    #  OR e.g. "SIP/2.0 200 OK" for a response
    line = headers.shift
    if line.start_with?("SIP/2.0")
      (_, code, reason) = line.split
      fields['status_code'] = code.to_i
      fields['status_reason'] = reason
    else
      (method, request_uri, _) = line.split
      fields['method'] = method
      fields['request_uri'] = request_uri
    end

    # process the headers (name : value)
    headers.each do |header|
      name, value = header.split(':', 2)
      name = name.strip.downcase.gsub('-', '_')
      fields[name] = value.strip
    end
    @logger.debug? && @logger.debug("SIP fields ", fields)
  end

  public
  def filter(event)
    fields = Hash.new
    value = event[@source]

    case value
    when nil
      # Nothing to do
    when String
      parse(value, fields)
    else
      @logger.warn("SIP filter has no support for this type of data", :type => value.class, :value => value)
    end

    return if fields.empty?

    fields.each do |k, v|
      event[@prefix + k] = v if want_key(k)
    end
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::SIP
