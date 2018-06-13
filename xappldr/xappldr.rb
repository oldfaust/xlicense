require 'openssl'
require 'net/http'

# Checks if we have permissions to run the given application
def chk_prm(app)
    puts "Checking permissions for application: " + app
    # TODO Think about how to test against MITM because currently if we use
    # wrong CA file the server rejects us, but what will happen if the server
    # accepts us and returns unexpected certificate. Is the VERIFY_PEER flag
    # enough to handle this case???
    # verify_depth???
    # TODO Use 'cert' with preloaded string instead of ca_file because the
    # latter may make us more vulnerable.
    cafile = '../xlserver/xlserver.crt' 
    uri = URI('https://127.0.0.1/check?app=' + app)
    Net::HTTP.start(uri.host, uri.port, 
                    :use_ssl => true, 
                    :verify_mode => OpenSSL::SSL::VERIFY_PEER, 
                    :ca_file => cafile) do |http|
        req = Net::HTTP::Get.new uri
        res = http.request(req)
        #puts res.body
        if res.body.to_s != "You are good to go.\n"
            raise 'No permissions'
        end
    end
end

# Loads the obfuscated binary given by path
def ld_obf(pth)
    puts "Loading obfuscated binary: " + pth

end

def rn_mm(data)
    puts "Running in-memory binary"

end

################################################################################

app = "p3"
path = "/z/p3/p3.bin"

begin
    chk_prm(app)
    dt = ld_obf(path)
    rn_mm(dt)
rescue => exception
    puts exception
end
