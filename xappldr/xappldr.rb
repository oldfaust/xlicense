require 'openssl'
require 'optparse'
require 'net/http'

# The function and variable names are visible in the final obfuscated thing.
# I made them a bit cryptic because of this reason. It won't prevent anything
# but at least will make the hacking one idea harder.
#
################################################################################
# Parses command line options
def prs_cmdl
    rt_opts = {}
    OptionParser.new do |opts|
        opts.banner = "Usage: ruby xappldr.rb [options]"
        opts.on("-E", "--encrypt=FILE_PATH", String, 
                "Encrypts the given file") do |f|
            rt_opts[:enc_f] = f
        end
        opts.on("-T", "--to=FILE_PATH", String, 
                "Path to save the encrypted file") do |f|
            rt_opts[:enc_to] = f
        end
        opts.on("-R", "--run=FILE_PATH", String, 
                "Run the given executable file") do |f|
            rt_opts[:run_f] = f
        end
        opts.on("-H", "--help", "Prints help") do
            puts opts
            exit
        end
    end.parse!
    return rt_opts
end

################################################################################
# Encrypts and saves the encrypted data to the given file
def sv_enc(d, fpth)
    # TODO Just XOR the file data for now.
    # Later we'll use some encryption scheme
    dt = d.bytes.to_a # Don't modify the input data
    for i in 0...dt.length
        dt[i] = dt[i] ^ dt[i]
    end
    IO.binwrite(dt, fpth)
end

def ld_enc(fpth)
    # TODO Just XOR the file data for now.
    # Later we'll use some encryption scheme
    dt = IO.binread(fpth).bytes.to_a
    for i in 0...dt.length
        dt[i] = dt[i] ^ dt[i]
    end
    return dt
end

################################################################################
# Checks if we have permissions to run the given application
def chk_prm(app)
    # TODO Think about how to test against MITM because currently if we use
    # wrong CA file the server rejects us, but what will happen if the server
    # accepts us and returns unexpected certificate. Is the VERIFY_PEER flag
    # enough to handle this case???
    # verify_depth???
    # TODO Use 'cert' with preloaded string instead of ca_file because the
    # latter may make us more vulnerable.
    puts "Checking permissions for " + app
    cafile = '../xlserver/xlserver.crt' 
    uri = URI('https://127.0.0.1/check?app=' + app)
    Net::HTTP.start(uri.host, uri.port, 
                    :use_ssl => true, 
                    :verify_mode => OpenSSL::SSL::VERIFY_PEER, 
                    :ca_file => cafile) do |http|
        req = Net::HTTP::Get.new uri
        res = http.request(req)
        raise 'No run permissions' if res.body.to_s != "You are good to go.\n"
    end
end

################################################################################
# Makes temporary directory to be used from outside
def mk_tdr(&block)
    # TODO Make additional fake directories if needed
    Dir.mktmpdir(block)
end

################################################################################
# Runs the binary from provided memory buffer - almost :(.
# Unfortunately we can't access Linux functions like memfd_create without
# additional .so file. The latter would introduce hooking point and
# vulnerability. So, we need to write the file somewhere in the filesystem.
def rn_mm(data)
    mk_tdr { |dir|
        puts "Running the binary from dir: " + dir
    }
end

################################################################################

begin
    opts = prs_cmdl()
    if opts.has_key?("enc_f") and opts.has_key?("enc_to")
        sdt = IO.binread(opts[:enc_f])
        sv_enc(sdt, opts[:enc_to])
        puts "Encrypted binary saved to " + opts[:enc_to]
    elsif opts.has_key?("run_f")
        apth = opts[:run_f]
        chk_prm(File.basename(apth))
        dt = ld_enc(apth)
        rn_mm(dt)
    else
        raise "No needed options provided"
    end
rescue => exception
    puts exception
end
