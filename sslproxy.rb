require 'socket'
require 'openssl'
require 'logger'
require 'uri'

class SSLProxy
  def initialize(port, opt = {}) 
    @proxy = TCPServer.new(port)
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
      
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.key = key
      ctx.cert = cert
      ctx.ca_file="root.pem"
      ssl_contexts[subject] = ctx
    }
    
  end

  def upstream_proxy?
    #are we forwarding traffic to an upstream proxy (vs. directly to
    #host)
    not (upstream_host.nil? or upstream_port.nil?)
  end

  def start
    loop do
      client = @proxy.accept
      Thread.new(client) { |client|
        begin
          self.handle_visible_proxy client
          client.close
        rescue
          $LOG.error($!)
        end
      } 
    end
  end

  def get_request(client)
    request = ""
      while l = client.gets and l != "\r\n"
        request << l
      end
    request << "\r\n"
  end

  def connect_ssl(host, port)
    socket = TCPSocket.new(host,port)
    ssl = OpenSSL::SSL::SSLSocket.new(socket)
    ssl.sync_close = true
    ssl.connect
  end

  def grab_cert(host, port)
    c = self.connect_ssl host, port
    c.peer_cert
  end
  
  def handle_visible_proxy(client)
    #this is the visible proxy mode, the client will send us an
    #unencrypted CONNECT request before we begin the SSL handshake
    #we ascertain the host/port from there
    request = get_request client
    #if the first line is  "CONNECT host:port HTTP/1.1\r\n" we're in
    #ssl MitM mode, otherwise, pass this along untouched.
    method, addr, protocol = request.split('\n')[0].split
    if method == "CONNECT"
      host, port = addr.split ':'
      if port.nil?
        port = 443
      else
        port = port.to_i
      end

      #connect to the server and forge the correct cert (using the same
      #subject as the server we connected to)
      if self.upstream_proxy?
        cert = self.grab_cert host, port
        server = self.connect_ssl @upstream_host, @upstream_port
      else
        server = self.connect_ssl host, port
        cert = server.peer_cert
      end
      ctx = @ssl_contexts[cert.subject]
      client.write "HTTP/1.0 200 Connection established\r\n\r\n"
      #initiate handshake
      ssl_client = OpenSSL::SSL::SSLSocket.new(client, ctx)
      ssl_client.accept
      self.create_pipe ssl_client, server
    else
      uri = URI(addr)
      host = uri.host
      port = uri.port
      #we're just passing through unencrypted data
      if self.upstream_proxy?
        server = TCPSocket.new(@upstream_host, @upstream_port)
      else
        server = TCPSocket.new(host, port)
      end
      #we pass along the request we cached
      self.create_pipe client, server, request
    end
  end


  def create_pipe(client, server, initial_request = nil)
    begin
      if initial_request
        server.write initial_request
        $LOG.info("Client: #{initial_request}")
      end
      Thread.new(client, server) { |client, server| # server => client
        while not (client.closed? or server.eof?)
          data = server.readpartial(1024)
          $LOG.info("Server: #{data}")
          client.write data
        end
      }
      # client => server
      while not (server.closed? and client.closed?)
        request = self.get_request client
        $LOG.info("Client: #{request}")
        server.write request
      end
      if not client.closed?
        client.close
      end
      if not server.closed?
        server.close
      end
    rescue
      if not client.closed?
        client.close
      end
      if not server.closed?
        server.close
      end
      $LOG.error("Error: #{$!}")
    end
  end
end

$LOG = Logger.new($stdout)
$LOG.sev_threshold = Logger::ERROR
#s = SSLProxy.new(8008, :upsteam_host => "localhost", :upstream_port => 8080)
s = SSLProxy.new(8008)

s.start

