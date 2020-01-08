#!/usr/bin/env ruby

times = []
(0..5000).each {|n|
    starttime = Time.now
    `echo ^D | ./tool/bssl client -connect localhost:4567 -min-version tls1.3`
    endtime = Time.now
    times << (endtime - starttime)
}

puts times.inject{ |sum, el| sum + el }.to_f / times.size