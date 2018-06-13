require 'openssl'
require 'net/http'

app = 'p3'
cafile = '../xlserver/xlserver.crt' 
uri = URI('https://127.0.0.1/check?app=' + app)

# TODO Think about how to test against MITM because currently if we use
# wrong CA file the server rejects us, but what will happen if the server
# accepts us and returns unexpected certificate. Is the VERIFY_PEER flag
# enough to handle this case???
# verify_depth???

begin
    Net::HTTP.start(uri.host, uri.port, 
                    :use_ssl => true, 
                    :verify_mode => OpenSSL::SSL::VERIFY_PEER, 
                    :ca_file => cafile) do |http|
        req = Net::HTTP::Get.new uri
        res = http.request(req)
        puts res.body
    end
rescue => exception
    puts exception
end
