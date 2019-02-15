# An implementation based on secure mail protocol
## Introduction
This is the server implementation of "Safe Data Transfer Protocol", as a NodeBB plugin.

SMTP(Simple Mail Transfer Protocol)
Which is a set of rules for transferring mail from source address to destination address, which controls the way the mail is transferred. It is a solution for information exchange for users under different service providers. But its data can be maliciously falsified or forged, user information can be attacked, and there is a lot of spam.

SDTP(Safe Date Transfer Protocol)provides secure, privacy-protected, and efficient data exchange for users under different service providers.

1. The SDTP user authentication system is based on a zero-knowledge proof digital signature, so
* SDTP does not generate spam messages.
* The user's email information will not be maliciously altered or forged by hackers or service providers.

2. the SDTP data transmission mode is also based on zero-knowledge proof, and the two sides of the message interaction are protected by privacy.
* When sending an email, the mail service provider only knows that there is an email message to be sent, but the recipient information cannot be known.
* When the mail is delivered, the mail service provider only knows who the recipient is, but cannot know the sender information of the mail.

3. when the SDTP communication data is attacked, for example, the service provider maliciously denies the service or the hacker intercepts the message, which will leave a track and notify the user. SDTP's service providers are multi-centralized, which is somewhat similar to the transaction record mechanism in Bitcoin, in which unless all possible node does not record transaction for an address.

## Install

    cd NodeBB
    git clone https://github.com/maikejonne/safeemail nodebb-plugin-semail
    npm install ./nodebb-plugin-semail
open page of NodeBB Plugin, find

![Unactive][1]

click Active

![Active][2]
## API
[API Description][3]


  [1]: https://raw.githubusercontent.com/maikejonne/safeemail/master/docs/unactive.png
  [2]: https://raw.githubusercontent.com/maikejonne/safeemail/master/docs/active.png
  [3]: https://maikejonne.github.io/safeemail/
