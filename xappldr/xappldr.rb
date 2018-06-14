require 'openssl'
require 'optparse'
require 'net/http'
require 'tmpdir'

# The function and variable names are visible in the final obfuscated thing.
# I made them a bit cryptic because of this reason. It won't prevent anything
# but at least will make the hacking one idea harder.
#
# TODO Remove these at some point in order to not be visible in the decompiled
# .class file.
# Password - Digest::SHA256.hexdigest("You are good to go.")
P = "2f41fdb0419fea6b7573221b2e35d11a147b89c297843740cb191388877e93c2"
# Salt - Digest::MD5.hexdigest("You are good to go.")
S = "6ff957ea573e020fac47857ea7ea1891"
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
        opts.on("-C", "--cmline=COMMAND_LIN_ARGS", String, 
                "The command line arguments which "+ 
                "should be given to the spawned process") do |c|
            rt_opts[:cm_ln] = c
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
# Note that the function modifies its input data.
def sv_enc(dt, fpth)
    # TODO Later we'll use some better encryption scheme
    # The IV could be randomly generated and inserted somewhere in the
    # binary data and later obtained from there. It's length is know.
    cph = OpenSSL::Cipher::AES256.new(:CBC)
    ki = OpenSSL::PKCS5.pbkdf2_hmac_sha1(P, S, 2000, cph.key_len + cph.iv_len)
    cph.encrypt
    cph.key = ki[0, cph.key_len]
    cph.iv = ki[cph.key_len, cph.iv_len]
    IO.binwrite(fpth, cph.update(dt) + cph.final)
end

def ld_enc(fpth)
    # TODO Just XOR the file data for now.
    # Later we'll use some encryption scheme
    dt = IO.binread(fpth)
    cph = OpenSSL::Cipher::AES256.new(:CBC)
    ki = OpenSSL::PKCS5.pbkdf2_hmac_sha1(P, S, 2000, cph.key_len + cph.iv_len)
    cph.decrypt
    cph.key = ki[0, cph.key_len]
    cph.iv = ki[cph.key_len, cph.iv_len]
    return cph.update(dt) + cph.final
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
    cafile = '../xlserver/xlserver.crt' 
    uri = URI('https://127.0.0.1/check?app=' + app)
    Net::HTTP.start(uri.host, uri.port, 
                    :use_ssl => true, 
                    :verify_mode => OpenSSL::SSL::VERIFY_PEER, 
                    :ca_file => cafile) do |http|
        req = Net::HTTP::Get.new uri
        res = http.request(req)
        raise 'No run permissions' if Digest::SHA256.hexdigest(res.body) != P
    end
end

################################################################################
# Makes temporary directory to be used from outside
def mk_tdr(&block)
    # TODO Make additional fake directories if needed
   # Dir.mktmpdir(nil, '/tmp/test/', &block)
    FileUtils.mkdir_p('/tmp/test/best')
    block.call('/tmp/test/best')
end

################################################################################
# Runs the binary from provided memory buffer - almost :(.
# Unfortunately we can't access Linux functions like memfd_create without
# additional .so file. The latter would introduce hooking point and
# vulnerability. So, we need to write the file somewhere in the filesystem.
def rn_mm(data, bin, cl)
    mk_tdr { |dir|
        bp = "#{dir}/#{bin}"
        bp_cl = bp + ' ' + cl
        File.open(bp, File::CREAT|File::TRUNC|File::WRONLY, 0700) { |f|
            f.write(data)
        }
        puts "Running the binary: #{bp_cl}"
        pid = spawn(bp_cl)
        Process.wait(pid)
    }
end

################################################################################

begin
    opts = prs_cmdl()
    if opts.has_key?(:enc_f) and opts.has_key?(:enc_to)
        dt = IO.binread(opts[:enc_f])
        sv_enc(dt, opts[:enc_to])
        puts "Encrypted binary saved to " + opts[:enc_to]
    elsif opts.has_key?(:run_f) and opts.has_key?(:cm_ln)
        apth = opts[:run_f]
        ap = File.basename(apth)
        chk_prm(ap)
        dt = ld_enc(apth)
        rn_mm(dt, ap, opts[:cm_ln])
    else
        raise "No needed options provided"
    end
rescue => exception
    puts exception
end
