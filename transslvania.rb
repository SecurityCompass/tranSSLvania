#!/usr/bin/env ruby

require 'socket'
require 'openssl'
require 'logger'
require 'optparse'
require 'uri'

$CLIENT_HELLOS = ["\x16\x03", #First 2 bytes of ClientHellos this should (?) cover common SSL/TLS version
                  "\x80\x9e"]
$SO_ORIGINAL_DST = 80 #not defined in socket module
class Request # grabs an HTTP request from the socket
  # TODO this should probably be WEBrick::HTTPRequest
  attr_accessor :contents, :method, :host, :port
  def initialize(client, ssl=false)
    @contents = ""
    while l = client.readpartial(4096) and not l.end_with? "\r\n"
      @contents << l
    end
    @contents << l
    lines = @contents.split("\n")
    @method, addr, protocol = lines[0].split
    if self.connect_method? #addr is host:port
      @host, @port = addr.split ':'
      if @port.nil?
        @port = 443
      else
        @port = @port.to_i
      end
    else #addr is a uri
      uri = URI(addr)
      @host = uri.host || lines[1].split[1]
      @port = uri.port || (ssl ? 443 : 80)
    end
  end
  def connect_method?
    @method == "CONNECT"
  end
end


class SSLProxy
  def initialize(host, port, opt = {})
    @host = host
    @port = port
    @invisible = opt[:invisible] || false
    @upstream_host = opt[:upstream_host] || nil
    @upstream_port = opt[:upstream_port] || nil
    # use this to cache forged ssl certs (SSLContexts)
    @ssl_contexts = Hash.new { |ssl_contexts, subject|
      #we use a previously generated root ca
      root_key = OpenSSL::PKey::RSA.new File.open("root.key")
      root_ca = OpenSSL::X509::Certificate.new File.open("root.pem")
      
      #generate the forged cert
      key = OpenSSL::PKey::RSA.new 2048
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = Random.rand(1000)
      cert.subject = subject
      cert.issuer = root_ca.subject # root CA is the issuer
      cert.public_key = key.public_key
      cert.not_before = Time.now
      cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
      ef = OpenSSL::X509::ExtensionFactory.new cert, root_ca
      ef.create_ext("keyUsage","digitalSignature", true)
      ef.create_ext("subjectKeyIdentifier","hash",false)
      ef.create_ext("basicConstraints","CA:FALSE",false)
      cert.sign(root_key, OpenSSL::Digest::SHA256.new)

      #fill out the context
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.key = key
      ctx.cert = cert
      ctx.ca_file="root.pem"
      ssl_contexts[subject] = ctx
    }
    @proxy = TCPServer.new(@host, @port)
  end

  def upstream_proxy?
    #are we forwarding traffic to an upstream proxy (vs. directly to
    #host)
    not (@upstream_host.nil? or @upstream_port.nil?)
  end

  def start
    puts "Serving on #{@host}:#{@port}"
    loop do
      client = @proxy.accept
      Thread.new(client) { |client|
	begin
          if @invisible
            #we grab the 1st two bytes to see if they contain the magic number
            #for SSL ClientHello, and create an SSL socket accordingly
            bytes = client.recv(2, Socket::MSG_PEEK)  
            if $CLIENT_HELLOS.include? bytes
              $LOG.debug("First bytes #{bytes}, SSL ClientHello")
              dummy, port, host = client.getsockopt(Socket::SOL_IP, $SO_ORIGINAL_DST).unpack("nnN")
              cert = self.get_cert(host, port)
              ctx = @ssl_contexts[cert.subject]
              ssl_client = OpenSSL::SSL::SSLSocket.new(client,ctx)
              ssl_client.accept
              request = Request.new ssl_client, true
              self.request_handler_ssl ssl_client, request
            else
              $LOG.debug("First bytes #{bytes}, HTTP")
              request = Request.new client
              self.request_handler client, request
            end
          else
            request = Request.new client
            self.request_handler client, request
          end
        rescue
          $LOG.error($!)
        end
      } 
    end
  end

  def connect_ssl(host, port, initial = nil)
    socket = TCPSocket.new(host,port)
    if initial
      socket.write initial << "\r\n"
      #TODO: interpret this and error out here if its not 200?
      dummy = (socket.readpartial(4096)) rescue nil
    end
    ssl = OpenSSL::SSL::SSLSocket.new(socket)
    ssl.sync_close = true
    ssl.connect
  end

  def get_cert(host, port)
    c = self.connect_ssl host, port
    c.peer_cert
  end
  
  def request_handler(client, request)
    #if this is the visible proxy mode, the client will send us an
    #unencrypted CONNECT request before we begin the SSL handshake
    #we ascertain the host/port from there
    if request.connect_method?
      #connect to the server and forge the correct cert (using the same
      #subject as the server we connected to)
      if self.upstream_proxy?
        cert = self.get_cert request.host, request.port
        server = self.connect_ssl @upstream_host, @upstream_port
      else
        server = self.connect_ssl request.host, request.port
        cert = server.peer_cert
      end
      ctx = @ssl_contexts[cert.subject]
      client.write "HTTP/1.0 200 Connection established\r\n\r\n"
      #initiate handshake
      ssl_client = OpenSSL::SSL::SSLSocket.new(client, ctx)
      ssl_client.accept
      self.create_pipe ssl_client, server, initial_request
    else
      #we're just passing through unencrypted data
      if self.upstream_proxy?
        server = TCPSocket.new(@upstream_host, @upstream_port)
      else
        server = TCPSocket.new(request.host, request.port)
        #server.write request.contents
        #server.write "\r\n"
      end
      #we pass along the request we cached
      self.create_pipe client, server, request
    end
  end

  def request_handler_ssl(ssl_client, request)
    if self.upstream_proxy?
      server = self.connect_ssl @upstream_host, @upstream_port, "CONNECT #{request.host}:#{request.port} HTTP/1.1\r\n"
    else
      server = self.connect_ssl request.host, request.port
    end
    self.create_pipe ssl_client, server, request
  end
  
  def create_pipe(client, server, initial_request)
    if initial_request
      server.write initial_request.contents
     # server.write "\r\n"
      server.flush
      $LOG.info("#{Thread.current}: client->server (initial) #{initial_request.inspect}")
    end
    while true
      # Wait for data to be available on either socket.
      (ready_sockets, dummy, dummy) = IO.select([client, server])
      begin
        ready_sockets.each do |socket|
          if socket == client #and not socket.eof?
            # Read from client, write to server.
            request = Request.new client
            # we may get requests for another domain coming down
            # this pipe if we are a visible proxy 
            # if wer're not proxied, we restart the handler
            unless @invisible or self.upstream_proxy?
              if request.host != initial_request.host or request.port != initial_request.port
                #we can also close the connection here??
                #server.close
                #client.close
                self.request_handler client, request
                break
              end
            end
            $LOG.info("#{Thread.current}: client->server #{request.inspect}")
            server.write request.contents
            server.flush
          else
            # Read from server, write to client.
            (data = socket.readpartial(4096)) rescue nil
            $LOG.info("#{Thread.current}: server->client #{data.inspect}")
            client.write data
            client.flush
          end
        end
      rescue IOError
        $LOG.debug($!)
        break
      end
    end
    unless client.closed?
      client.close
    end
    unless server.closed?
      server.close
    end
  end
end

$LOG = Logger.new($stdout)
$LOG.sev_threshold = Logger::ERROR

options = {}
host = "localhost"
port = 8080
OptionParser.new do |opts|
  opts.banner = "Usage: example.rb [options]"
  opts.on("-l", "--listen HOST:PORT", "Host and port to listen on") do |address|
    h, p = address.split(':')
    if h.nil? or p.nil?
      $stderr.puts "address must be in the form host:port"
      exit
    end
    host = h
    port = p
  end
  opts.on("-p", "--upstream_proxy HOST:PORT", "Use an upstream proxy") do |proxy|
    host, port = proxy.split(':')
    if host.nil? or port.nil?
      $stderr.puts "upstream proxy must be in the form host:port"
      exit
    end
    options[:upstream_host] = host
    options[:upstream_port] = port
  end
  opts.on("-i", "--invisible", "Run in invisible proxy mode (use iptables to forward traffic to SSLProxy)") do 
    options[:invisible] = true
  end
  opts.on("-d", "--debug", "Enable debug output") do 
    $LOG.sev_threshold = Logger::DEBUG
  end
end.parse!

puts options
s = SSLProxy.new(host, port, options)
s.start

