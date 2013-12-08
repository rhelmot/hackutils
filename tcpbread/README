tcpbread
========

*If tcpdump is too meaty for you, add some bread for a delicious traffic sandwich~*

This is just a fun little program I wrote up in literally 6 hours straight 
because I'm awesome. You can use it to monitor tcpdump for whatever traffic 
you're looking for via regexes or python. Run it EXACTLY like so:

`tcpdump -i <interface> -nSv -X | python tcpbread.py [options] <config files>`

Run tcpbread without any arguments to learn about the options format. Long 
story short, you can specify a lot of stuff about the format of the output 
for successful matches.

The configuration files specify what ports to care about and what data should
constitute a match on each port.

I've had some latencies of up to ten seconds in terms of data sent to reported 
here, but the timestamps reported are still going to be correct.

If it crashes, first check that your tcpdump version is 4.2.1 OR 4.4.0 and 
you're running tcpdump with *exactly* the arguments I put up there. I have it 
very fine-tuned to the specific output format, and if even a single byte gets 
off for some parts, it's going to crash and burn. If it's still crashing, send 
me the output of the crash while it's running with debugging output enabled.

Lastly, you're welcome.
