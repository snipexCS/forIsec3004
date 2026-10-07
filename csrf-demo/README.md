to run a demo
first run npm install

then in terminal typr cd csrf-demp

run node vulnerable-app.js

then go to http://localhost:4000/account

after that in second terminal run attacker-server.js

then after loggin in  http://localhost:4000/account in same window go to http://localhost:5050(this is attackers website, we are simulating that user after logged in was tricked by attacker to use a link to his website)

after visiting a link go back to  http://localhost:4000/account  and refresh a page you should be able to see that the email was modified 

////////////////////////////////

now instead of starting vulenrable-app.js run mitigated-app.js
and repeat same instructions, you should now see that the email no longer changes 

to see more detailed logs open log files 