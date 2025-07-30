# Working version of my Multiple Authority Attribute Based Encryption server and client library
## Designed off of code provided form New Mexico State University and in conjunction with George Torres from NMSU
Primarily this was designed as a proof of concept for testing some ideas around doing attribute based encryption with secure hardware,
the project fell to the backburner after completion but I thought it would be a decent show of some (messy) research code that I am now allowed to distribute.
Most requirements can be found within the main import.

I may revist this is the future and clean it up into a fully functional library in the future

How it Works:

functionally it imitates having multiple third-party authorities for handing out attribute keys, the best way to think about this- and the best use case is as such. You the server, and the client do not trust each other, however you both trust some third-party to be (some what) legitimate. Ie, both consider Cloudflare or Google, or Amazon to have a business interest to not collude with bad actors. Therefore we each individually give our information to this third-party and they certify that we are who we claim, this can be done through challenge response, attribute challenge, etc. We then both contact more authorities and do the same, the idea being that I now have a collection of attributes from multiple authorities who are unlikely to collude with both either participant, nor any other authority. Then a participant can encrypt a message with a particular attributes from particular authorities. Example, I can encode a message that I only want google employees, who are also AWS users to be able to decrypt. then I can send out this message via discovery, and everyone who has both of those keys, or more, then can dencrypt the message. 

In this base we create 3 Authorities, (Json files for this instance) and a server is able to request any amount or permutation of attributes from each authority, the client can then send a message encoded with any attribute from any authority, and the server will then decrypt what has been sent. 
