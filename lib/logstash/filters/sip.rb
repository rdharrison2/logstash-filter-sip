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
           "status_code", "status_reason", "content_length",
           "call_id", "contact", "contact_uri", "contact_expires", "cseq",
           "from_uri", "from_display_name", "from_tag", "from_epid",
           "to_uri", "to_display_name", "to_tag", "to_epid",
           "user_agent"]

  # An array specifying the headers/values to not add to the event
  config :exclude_keys, :validate => :array, :default => []

  class InvalidURIError < StandardError; end

  public
  def register
  end # def register

  def want_key(key)
    return false if not @include_keys.empty? and not @include_keys.include?(key)
    return false if @exclude_keys.include?(key)
    return true
  end

  def parse_uri(name, text)
    # contact-param  =  (name-addr / addr-spec) ...
    # name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
    # addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
    # display-name   =  *(token LWS)/ quoted-string
    # quoted-string  =  SWS DQUOTE *(qdtext / quoted-pair ) DQUOTE
    # token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
    #                  / "_" / "+" / "`" / "'" / "~" )
    # Lets approximate this with a regex :)
    re_uri = '(?:sip:|sips:|tel:)[^; ]+'
    re_qstr = '"(?<display_name>(?:[^"]|\\")*)"'
    re_value = "^(?:\s*(?:(?<display_name>[^\"]+)|#{re_qstr})?\s*<(?<uri>[^>]+)>|(?<uri>#{re_uri}))\s*(?<params>.+)?$"
    r = Regexp.new(re_value)
    m = r.match(text)
    if not m
      raise InvalidURIError, "Failed to regex URI #{name}: #{text} (regex=#{r})"
    end
    #print "m: ", m, "\n"
    parts = { "uri" => m['uri'].strip }
    display_name = m['display_name'] ? m['display_name'].strip : ""
    if display_name != ""
      parts['display_name'] = display_name
    end
    if m['params']
      m['params'].split(';').each do |param|
        param = param.strip
        next if param == ""
        #print "param: ", param, "\n"
        if param.include? '='
          (k,v) = param.split('=', 2)
          parts[k] = v
        else
          parts[param] = true
        end
      end
    end
    return parts
  end

  def parse(text, fields)
    # replace "\r\n" for new-lines, and strip leading whitespace
    text = text.gsub("\r\n", "\n")
    # replace ^M for new-lines, and strip leading whitespace
    text = text.gsub(@line_split, "\n").lstrip
    # split into first-line+header/body via two new-lines
    parts = text.split("\n\n", 2)
    # save the body & content length if it exists
    fields['content_length'] = 0
    if parts.length > 1
      fields['body'] = parts[1]
      # Note: content length needs to count new-lines as \r\n!
      fields['content_length'] = parts[1].gsub("\n","\r\n").length
    end
    # split into first line and headers
    parts = parts[0].split("\n", 2)
    # first line is e.g. "REGISTER sip:rd.pexip.com SIP/2.0" for a request
    #  OR e.g. "SIP/2.0 200 OK" for a response
    line = parts[0]
    if line.start_with?("SIP/2.0")
      (_, code, reason) = line.split(/\s/, 3)
      fields['status_code'] = code.to_i
      if reason.nil?
        fields['status_reason'] = nil
      else
        fields['status_reason'] = reason.strip
      end
    else
      (method, request_uri, _) = line.split
      fields['method'] = method
      fields['request_uri'] = request_uri
    end

    # process the headers (name : value)
    if parts.length > 1
      fields['headers'] = parts[1]
      headers = parts[1].split("\n")
      headers.each do |header|
        name, value = header.split(':', 2)
        if name.nil? || value.nil?
          @logger.debug? and @logger.debug("invalid header: <#{header}>")
          next
        end
        name = name.strip.downcase.gsub('-', '_')
        value = value.strip
        # handle integer values
        value = value.to_i if name == 'content_length'
        fields[name] = value
        # Note: contact header may have value *
        if ['to', 'from', 'contact'].include?(name) and value != '*'
          parts = parse_uri(name, value)
          parts.each do |k, v|
            #print "k: ", k, " v: ", v, "\n"
            fields[name + '_' + k] = v
          end
        end
      end
    end
    #print "SIP fields: ", fields, "\n"
    @logger.debug? && @logger.debug("SIP fields ", fields)
  end

  public
  def filter(event)
    fields = Hash.new
    value = event.get(@source)

    case value
    when nil
      # Nothing to do
    when String
      begin
        parse(value, fields)
      rescue
        @logger.error("Failed to parse SIP message", :value => value)
        raise
      end
    else
      @logger.warn("SIP filter has no support for this type of data", :type => value.class, :value => value)
    end

    return if fields.empty?

    #print "include keys: ", @include_keys, "\n"
    #print "exclude keys: ", @exclude_keys, "\n"
    fields.each do |k, v|
      event.set(@prefix + k, v) if want_key(k)
    end
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::SIP
