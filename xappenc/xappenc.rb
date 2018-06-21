#!/usr/bin/env ruby

require 'openssl'
require 'optparse'

def parse_cmd_line
    rt_opts = {}
    OptionParser.new do |opts|
        opts.banner = "Usage: xappenc.rb [options]"
        opts.on("-E", "--encrypt=FILE_PATH", String, 
                "Encrypts the given file") do |f|
            rt_opts[:enc_f] = f
        end
        opts.on("-T", "--to=FILE_PATH", String, 
                "Path to save the encrypted file") do |f|
            rt_opts[:enc_to] = f
        end
        opts.on("-H", "--help", "Prints help") do
            puts opts
            exit
        end
    end.parse!
    return rt_opts
end

def save_encrypted(dt, fpth)
    phrase = 'XGFqCq6xm0gtFlbLDM0wRa1dm3FShwBerKhvebzA6So'
    pass = Digest::SHA256.hexdigest(phrase)
    salt = Digest::MD5.hexdigest(phrase)

    cph = OpenSSL::Cipher::AES256.new(:CBC)
    iv = OpenSSL::Random.pseudo_bytes(cph.iv_len)
    cph.encrypt
    cph.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass, salt, 2000, cph.key_len)
    cph.iv = iv
    # Note that we are storing the IV at the beginning of the encrypted file
    IO.binwrite(fpth, iv + cph.update(dt) + cph.final)
end

################################################################################

begin
    opts = parse_cmd_line()
    if opts.has_key?(:enc_f) and opts.has_key?(:enc_to)
        dt = IO.binread(opts[:enc_f])
        save_encrypted(dt, opts[:enc_to])
        puts "Encrypted binary saved to " + opts[:enc_to]
    else
        raise "No needed options provided"
    end
rescue => exception
    puts exception
end
