https://likegeeks.com/expect-command/

Expect Command

Before we talk about expect command, Let’s see some of the expect command which used for interaction:

spawn                  Starting a script or a program.

expect                  Waiting for program output.

send                      Sending a reply to your program.

interact                Allowing you in interact with your program.

    The spawn command is used to start a script or a program like the shell, FTP, Telnet, SSH, SCP, and so on.
    The send command is used to send a reply to a script or a program.
    The Expect command waits for input.
    The interact command allows you to define a predefined user interaction.

We are going to type a shell script that asks some questions and we will make an Expect script that will answer those questions.

First, the shell script will look like this:
	Refer questions file
Now we will write the Expect scripts that will answer this automatically:
	Refer answerbot file

The first line defines the expect command path which is  #!/usr/bin/expect .

On the second line of code, we disable the timeout. Then start our script using spawn command.

We can use spawn to run any program we want or any other interactive script.

The remaining lines are the Expect script that interacts with our shell script.

The last line if the end of file which means the end of the interaction.

Now Showtime, let’s run our answer bot and make sure you make it executable.

$ chmod +x ./answerbot

$./answerbot

Cool!! All questions are answered as we expect.

If you get errors about the location of Expect command you can get the location using the which command:

$ which expect

We did not interact with our script at all, the Expect program do the job for us.

The above method can be applied to any interactive script or program.Although the above Expect script is very easy to write, maybe the Expect script little tricky for some people, well you have it.

 
Using autoexpect

To build an expect script automatically, you can the use autoexpect command.

autoexpect works like expect, but it builds the automation script for you. The script you want to automate is passed to autoexpect as a parameter and you answer the questions and your answers are saved in a file.

$ autoexpect ./questions

A file is generated called script.exp contains the same code as we did above with some additions that we will leave it for now.

If you run the auto generated file script.exp, you will see the same answers as expected:

Awesome!! That super easy.

There are many commands that produce changeable output, like the case of FTP programs, the expect script may fail or stuck. To solve this problem, you can use wildcards for the changeable data to make your script more flexible.


