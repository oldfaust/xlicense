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
        opts.on("-B", "--bind_ip=BIND_IP", String, 
                "IP to bind the client") do |i|
            rt_opts[:bn_ip] = i
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
    iv = OpenSSL::Random.pseudo_bytes(cph.iv_len)
    cph.encrypt
    cph.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(P, S, 2000, cph.key_len)
    cph.iv = iv
    IO.binwrite(fpth, iv + cph.update(dt) + cph.final)
end

def ld_enc(fpth)
    # TODO Later we'll use some better encryption scheme
    # The IV could be randomly generated and inserted somewhere in the
    # binary data and later obtained from there. It's length is know.
    puts 'Loading ' + fpth
    dt = IO.binread(fpth)
    cph = OpenSSL::Cipher::AES256.new(:CBC)
    cph.decrypt
    cph.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(P, S, 2000, cph.key_len)
    cph.iv = dt[0, cph.iv_len]
    return cph.update(dt[cph.iv_len .. -1]) + cph.final
end

################################################################################
# Calculates SHA256 checksum of given file
def cs_fl(fl)
    dt = IO.binread(fl)
    return Digest::SHA256.hexdigest(dt)
end

################################################################################
# Checks if we have permissions to run the given application
def chk_prm(app, bip, cs)
    # TODO Think about how to test against MITM because currently if we use
    # wrong CA file the server rejects us, but what will happen if the server
    # accepts us and returns unexpected certificate. Is the VERIFY_PEER flag
    # enough to handle this case???
    # verify_depth???
    # TODO Use 'cert' with preloaded string instead of ca_file because the
    # latter may make us more vulnerable.
    cafile = '../xlserver/xlserver.crt'
    rq = 'https://127.0.0.1/check?app=' + app + '&ver=' + V + '&csum=' + cs;
    uri = URI(rq)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.ca_file = cafile
    http.local_host = bip
    http.start {  |httpo|
        req = Net::HTTP::Get.new uri
        res = httpo.request(req)
        raise 'No run permissions' if Digest::SHA256.hexdigest(res.body) != P
    }
end

################################################################################
# Makes fake directories and returns the last one to be used.
def mk_fdrs
    l1_dr = rand(4...6)
    l2_dr = rand(6...8)
    l3_dr = rand(8...10)
    drs = []
    tdrs = [] 
    arr = [*('A'..'Z'), *('a'..'z'), *('0'..'9')]
    for i in 0..l1_dr
        dir1 = arr.sample(8).join 
        tdrs.push('/tmp/' + dir1)
        for j in 0..l2_dr
            dir2 = arr.sample(8).join 
            for k in 0..l3_dr
                dir3 = arr.sample(8).join
                drs.push('/tmp/' + dir1 + '/' + dir2 + '/' + dir3)
            end
        end
    end
    for d in drs
        FileUtils.mkdir_p(d)
    end
    return drs[-1], tdrs
end

# Makes temporary directory to be used from outside
def mk_tdr(&block)
    bd, tdrs = mk_fdrs()
    begin
        # Make additional temporary dir in the exec directory
        Dir.mktmpdir(nil, bd, &block)
    ensure
        #puts 'Removing dirs ' + tdrs.to_s
        FileUtils.rm_r(tdrs, :force => true)
    end
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
        #puts "Running the binary: #{bp_cl}"
        pid = spawn(bp_cl)
        # The below sleep is kind of unfortunate but I couldn't figure out a
        # another way to simulate timed wait.
        # Basically if we try to start invalid ELF binary we'll get non nil
        # status.
        sleep(2)
        Process.wait2(pid, Process::WNOHANG)
        if ($? != nil)
            raise 'Failed to start the binary'
        end
    }
end

################################################################################
# Do not remove the below comment! It's replaced on build with the version!
# V =

begin
    opts = prs_cmdl()
    if opts.has_key?(:enc_f) and opts.has_key?(:enc_to)
        dt = IO.binread(opts[:enc_f])
        sv_enc(dt, opts[:enc_to])
        puts "Encrypted binary saved to " + opts[:enc_to]
    elsif opts.has_key?(:run_f) and opts.has_key?(:cm_ln)
        apth = opts[:run_f]
        bnip = opts[:bn_ip]
        if bnip == nil
            raise "Provide bind IP"
        end
        ap = File.basename(apth)
        cs = cs_fl("./xappldr.class")
        chk_prm(ap, bnip, cs)
        dt = ld_enc(apth)
        rn_mm(dt, ap, opts[:cm_ln])
    else
        raise "No needed options provided"
    end
rescue => exception
    puts exception
end
