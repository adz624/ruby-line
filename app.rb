require 'thrift'
$:.push('line-protocol/gen-rb')
require 'line_main_constants'
require 'line_constants'
require 'talk_service'
require 'json'
require 'open-uri'
require 'openssl'
require './helper'



LINE_DOMAIN = "http://gd2.line.naver.jp"
LINE_HTTP_URL          = LINE_DOMAIN + "/api/v4/TalkService.do"
LINE_HTTP_IN_URL       = LINE_DOMAIN + "/P4"
LINE_CERTIFICATE_URL   = LINE_DOMAIN + "/Q"
LINE_SESSION_LINE_URL  = LINE_DOMAIN + "/authct/v1/keys/line" # email
LINE_SESSION_NAVER_URL = LINE_DOMAIN + "/authct/v1/keys/naver" # id
ip          = "127.0.0.1"
version     = "3.7.0"
com_name    = "eddie"
revision    = 0

email = ''
password = ''

json = JSON.parse(open(LINE_SESSION_LINE_URL).read)
session_key = json['session_key']

message = "#{encode_message(session_key)}#{encode_message(email)}#{encode_message(password)}"

keyname, n, e = json['rsa_key'].split(",")

# puts session_key
# puts "\n"
# puts keyname
# puts "\n"
# puts "message: #{message.inspect}, n: #{n.to_i(16)} e: #{e.to_i(16)}"

pub_key = OpenSSL::PKey::RSA.new
pub_key.n, pub_key.e = n.to_i(16), e.to_i(16)

crypto = Digest.hexencode(pub_key.public_encrypt(message))
# ==================
os_version = "10.9.4-MAVERICKS-x64"
user_agent = "DESKTOP:MAC:#{os_version}(#{version})"
app_code = "DESKTOPMAC\t#{version}\tMAC\t#{os_version}"
headers = { "User-Agent" => user_agent, "X-Line-Application" => app_code }
# ==================
transport = Thrift::HTTPClientTransport.new(LINE_HTTP_URL)
transport.add_headers(headers)
# transport = Thrift::BufferedTransport.new()
protocol = Thrift::CompactProtocol.new(transport)
client = Line::TalkService::Client.new(protocol)
begin
  msg = client.loginWithIdentityCredentialForCertificate(Line::IdentityProvider::LINE, email, password, true, ip, com_name, "")
  puts msg.inspect
rescue Exception => e
  puts e.inspect
end

# transport.open