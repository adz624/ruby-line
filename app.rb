require 'thrift'
$:.push('gen-rb')
require 'line_main_constants'
require 'line_constants'
require 'talk_service'
require 'json'
require 'open-uri'
require 'openssl'
require './helper'
require 'net/http'


email = ''
password = ''

# ====================================================
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
  # 1. 第一次登入
  msg = client.loginWithIdentityCredentialForCertificate(Line::IdentityProvider::LINE, email, password, true, ip, com_name, "")
  puts "please input pin code in your devise: #{msg.pinCode}"
  
  # 2. blocking request 等待輸入 pin code
  uri = URI(LINE_CERTIFICATE_URL)
  req = Net::HTTP::Get.new(uri)
  req['X-Line-Access'] = msg.verifier
  Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  

  # 3. 取得 cert & authToken
  auth_info = client.loginWithVerifierForCertificate(msg.verifier)
  transport.add_headers("X-Line-Access" => auth_info.authToken)

  # 4. 使用 auth token 重新登入 (back to step 1.)
  client.loginWithIdentityCredentialForCertificate(Line::IdentityProvider::LINE, email, password, true, ip, com_name, "")
  

  # === 已取得權限

  # a. 得到 revision
  revision = client.getLastOpRevision()
  puts "revision: #{revision}"

  # b. 得到 profile information
  profile = client.getProfile()
  puts "LineID: #{profile.userid}, phone: #{profile.phone}, displayName: #{profile.displayName}, regionCode: #{profile.regionCode}"

  # c. 得到 contact ids
  contact_ids = client.getAllContactIds()
  puts contact_ids.inspect

rescue Exception => e
  puts e.inspect
end

# transport.open