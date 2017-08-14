#!/usr/bin/env python
# Created for HTor project
# basic ideas are stated in submitted 2018 infoCom paper:
#       Link Us If You Can: Enabling Unlinkable Communication on the Internet
# For anonymity of this project, more details will be stated later.
from Tkinter import *
import time
import random
import sys
from tornado.httpclient import *
from tornado.httputil import *
import seccure
import hashlib
from urllib import pathname2url, url2pathname
from bs4 import BeautifulSoup
import string
import json
import os


normal_ids = ['body', 'header', 'content', 'date']
htor_website = "http://htor.tech/entry/haha-booy"
identity_file = 'htor'
folder = identity_file + '_friend/'


def set_new_pr():
    daily_pr = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50))
    return daily_pr


def touch(path):
    with open(path, 'a'):
        os.utime(path, None)


def load_friends_tags():
    # return a list consist of all friends' received_last and send_last hash
    frds = load_all_friends()
    flags = []
    for friend in frds:
        flags.append(str(friend['send_last']))
        flags.append(str(friend['received_last']))
    return flags


def handle_response(body):
    # a shaking process will receive a pub from the server for register.
    soup = BeautifulSoup(body, "lxml")
    # receive_time = int(time.time())
    # print (receive_time)
    # print (table_name + "receive")
    id_list = []
    for tag in soup.findAll(True, {'id': True}):
        id_list.append(tag['id'])

    # remove normal tags
    id_list = [x for x in id_list if x not in normal_ids]
    return id_list


def add_single_message(friend, msg, new_pub):
    #  produce the pub/pr for this msg
    t_friend_msg = {}
    me_pr = str(friend['my_pr'])
    send_time = str(int(time.time()))
    first = str(friend['received_message'])
    sign_msg = seccure.sign(msg, me_pr)
    rpub = url2pathname(friend['received_pub'])
    second = seccure.encrypt(new_pub + msg + sign_msg + send_time, str(rpub))
    print ("msg: %s" % msg)
    print ("sign_msg: %s" % sign_msg)
    print ("need pub: %s" % str(url2pathname(friend['my_pub'])))
    t_friend_msg['uid'] = str(friend['uid'])
    t_friend_msg['first'] = first
    t_friend_msg['second'] = str(pathname2url(second))
    return t_friend_msg


def send_all_messages(friend_msgs, new_pr):
    me_pr = str(user['pr'])
    # me_pub = str(user['pub']) #   user['pub'] is useless

    send_time = str(int(time.time()))
    user_auth = seccure.sign(send_time, me_pr)
    user_auth = pathname2url(user_auth)
    # if ';' in user_auth or user_auth[-1] == ' ':
    #     user_auth = manipulate(user_auth)
    http_client = HTTPClient()
    cookie = dict()
    cookie['Cookie'] = '_ga=GA1.1.' + str(user['uid']) + '.' + send_time + '; ' \
                       + 'user_auth=%s;' % user_auth
    cookie['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko)\
     Chrome/57.0.2987.133 Safari/537.36"

    # TODO:if need update key
    if new_pr:
        a = 1
        # msg = str(seccure.passphrase_to_pubkey(str(new_pr)))
        # en_new_pass = str(seccure.passphrase_to_pubkey(str(me_pub)))
        # temp_pass = seccure.encrypt(msg, en_new_pass)
        # # if ';' in temp_pass or temp_pass[-1] == ' ':
        # #     temp_pass = manipulate(temp_pass)
        # temp_pass = pathname2url(temp_pass)
        # cookie['Cookie'] += 'user_pass=%s; ' % temp_pass

    # add message from list friend_msgs
    count = 0
    for friend_msg in friend_msgs:
        cookie['Cookie'] += 'user_info'
        cookie['Cookie'] += '' if count == 0 else str(count)
        t_user_info = seccure.encrypt(friend_msg['uid'] + ' ' + friend_msg['first'] + ' ' + friend_msg['second'],
                                      str(url2pathname(user['spub'])))
        t_user_info = pathname2url(t_user_info)
        cookie['Cookie'] += '=%s; ' % t_user_info
        count += 1

    resp = http_client.fetch(htor_website, headers=cookie, request_timeout=200, connect_timeout=200)
    if not resp.code == 200:
        print("Error: %s" % resp.error)
        return 1
    return resp


def load_all_friends():
    friends = []
    for frname in os.listdir(folder):
        if not frname == '.DS_Store':
            with open(folder + frname, 'r') as f:
                content = f.readlines()
            friends.append(json.loads(content[0]))
    return friends


def load_one_friend(name):
    if os.path.isfile(folder + name):
        with open(folder + name, 'r') as single_f:
            single_content = single_f.readlines()
        return json.loads(single_content[0])
    else:
        return 1


def update_one_friend(friend):
    name = str(friend['name'])
    if not os.path.isfile(folder + name):
        touch(folder + name)
    with open(folder + name, 'w') as f:
        f.write(json.dumps(friend))


def register(name, initial_pr):
    # registration initial: produce a random uniqueId to get a spub to encrypt (pr, pub) for encryption between S and C.
    for _ in range(100):
        uniqueId = ''.join(random.choice(string.digits) for _ in range(9))
        cookie1 = dict()
        cookie1['Cookie'] = '_ga=GA1.1.' + uniqueId + '.' + str(int(time.time())) + '; '
        cookie1['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko)\
                     Chrome/57.0.2987.133 Safari/537.36"
        http_client1 = HTTPClient()
        resp1 = http_client1.fetch(htor_website, headers=cookie1, request_timeout=200, connect_timeout=200)
        contact_list = handle_response(resp1.body)
        if _ == 99:
            print ("Server %s doesn't permit registration!" % htor_website)
            return 1
        if len(contact_list) == 0:
            print ('The HTor server no longer works, please choose another one')
            return 1
            # exit(0)
        if not contact_list[0] == "bad":
            break
    print ('Server works fine!')
    spub = contact_list[0]

    # use spub to encrypt (pr, pub)
    register_time = int(time.time())
    user_auth = seccure.sign(str(register_time), initial_pr)
    user_auth = pathname2url(user_auth)

    new_pub = str(seccure.passphrase_to_pubkey(initial_pr))
    user_register_info = seccure.encrypt(uniqueId + ' ' + new_pub, url2pathname(spub))
    user_register_info = pathname2url(user_register_info)

    cookie2 = dict()
    cookie2['Cookie'] = '_ga=GA1.1.' + uniqueId + '.' + str(int(register_time)) + '; ' \
                        + 'user_auth=%s;' % user_auth
    cookie2['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko)\
             Chrome/57.0.2987.133 Safari/537.36"

    cookie2['Cookie'] += 'user_info'
    cookie2['Cookie'] += '=%s; ' % user_register_info
    http_client2 = HTTPClient()
    resp2 = http_client2.fetch(htor_website, headers=cookie2, request_timeout=200, connect_timeout=200)
    register_list = handle_response(resp2.body)
    if register_list[0] == uniqueId:
        # there are always some sensitive char in pub. Thus we choose convert pub.
        identity = {}
        identity['name'] = name
        identity['uid'] = uniqueId
        # identity['pw'] = user_password
        identity['pr'] = initial_pr
        identity['pub'] = str(pathname2url(new_pub))
        identity['spub'] = str(spub)
        with open(identity_file, 'w') as id_file:
            id_file.write(json.dumps(identity))
        return 1
    return 0


if not os.path.isfile(identity_file):
    touch(identity_file)
with open(identity_file, 'r') as f:
    content = f.readlines()
if len(content) == 0:
    tt_name = identity_file
    reg_stat = register(tt_name, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50)))
    if reg_stat == 1:
        pass
    else:
        exit(0)
    with open(identity_file, 'r') as f2:
        content = f2.readlines()
if not os.path.isdir(folder):
    os.mkdir(folder, 0755)
user = json.loads(content[0])


class WidgetsDemo:
    def __init__(self):
        frds = load_all_friends()
        window = Tk()
        window.title("Hello, %s" % user['name'])

        send_msg = Frame(window)
        send_msg.pack()
        cut_send_msg = Label(send_msg,
                        text="--------------------------------send message(length<= 50)---------------------------------")

        sm_0 = Label(send_msg, text="friend nickname: ")
        self.send_name = StringVar()
        self.sname_entry = Entry(send_msg, textvariable=self.send_name)
        if len(frds) == 1:
            self.sname_entry.insert(0, frds[0]['name'])

        sm_1 = Label(send_msg, text="message: ")
        self.send_msg = StringVar()

        self.smsg_entry = Entry(send_msg, textvariable=self.send_msg)

        sendm = Button(send_msg, text="Send message", command=self.send_one_message)

        cut_send_msg.grid(row=1, columnspan=4)
        sm_0.grid(row=2, column=1)
        self.sname_entry.grid(row=2, column=2)
        sm_1.grid(row=3, column=1)
        self.smsg_entry.grid(row=3, column=2)
        sendm.grid(row=3, column=3)

        msg_box = Frame(window)
        msg_box.pack()
        cut_msg_box = Label(msg_box,
                         text="--------------------------------------message box----------------------------------------")
        cut_msg_box.grid(row=1, column=1)
        self.text = Text(window)
        self.text.pack()
        self.text.insert(END, "Waiting for messages...\n")

        friend_list = Frame(window)
        friend_list.pack()
        cut_friend_list = Label(friend_list,
                         text="--------------------------------------friend list----------------------------------------")

        friend_lists = [str(frd['name']) for frd in frds]
        if len(friend_lists) == 0:
            self.friends_str = Label(friend_list, text="Add a friend now!")
        else:
            self.friends_str = Label(friend_list, text="Your friends: %s" % ' '.join(friend_lists))
        self.friends_str.grid(row=2, column=1)
        cut_friend_list.grid(row=1, column=1)


        frame1 = Frame(window)
        frame1.pack()
        cut_end1 = Label(frame1, text="--------------------------------------add friends----------------------------------------")
        cut_end1.grid(row=1,columnspan=4)


        frame2 = Frame(window)
        frame2.config(borderwidth=1)
        frame2.pack()

        label2_0 = Label(frame2, text="Give a nickname of your friend: ")
        self.fname = StringVar()
        self.fname_entry = Entry(frame2, textvariable=self.fname)

        label2_1 = Label(frame2, text="Enter the UID of your friend: ")
        self.fuid = StringVar()
        self.fuid_entry = Entry(frame2, textvariable=self.fuid)

        label2_2 = Label(frame2, text="Enter the public key of your friend: ")
        self.fpub = StringVar()
        self.fpub_entry = Entry(frame2, textvariable=self.fpub)

        addf = Button(frame2, text="Add friend", command=self.click_add_friend)

        cut_end2 = Label(frame2, text="-----------------------------------------------------------------------------------------")

        label2_0.grid(row=1, column=1)
        self.fname_entry.grid(row=1, column=2)
        label2_1.grid(row=2, column=1)
        self.fuid_entry.grid(row=2, column=2)
        label2_2.grid(row=3, column=1)
        self.fpub_entry.grid(row=3, column=2)
        addf.grid(row=3, column=3)
        cut_end2.grid(row=4,columnspan=4)

        # frame 3
        frame3 = Frame(window)
        frame3.pack()

        label3_1 = Label(frame3, text="UID: %s. Public key: " % user['uid'], bg="white")
        label3_2 = Label(frame3, text="%s" % url2pathname(user['pub']), bg="gray")
        btGetpub = Button(frame3, text="Copy key to clipboard", command=self.copy_pub)


        label3_1.grid(row=1, column=1)
        label3_2.grid(row=1, column=2)
        btGetpub.grid(row=1, column=3)

        # frame 4
        frame4 = Frame(window)
        frame4.pack()

        label4 = Label(frame4, text="The demo HTor server:")
        entry_name = Entry(frame4)
        entry_name.insert(0, htor_website)
        # entry_name.config(state='disabled')

        label4.grid(row=1, column=1)
        entry_name.grid(row=1, column=3, columnspan=2)

        window.mainloop()

    def processCheckbutton(self):
        print ("Check button is:"
               + ("checked" if self.v1.get() == 1 else "unchecked"))

    def processRadiobutton(self):
        print (("Red" if self.v2.get() == 1 else "Yellow")
               + " is selected.")

    def processButton(self):
        print ("Your name is " + self.name.get())

    def copy_pub(self):
        root = Tk()
        # keep the window from showing
        root.withdraw()
        return root.clipboard_append(url2pathname(user['pub']))

    def handle_all_response(self, body, flags, findex, send_msg, new_pr, new_pub):
        frds = load_all_friends()
        soup = BeautifulSoup(body, "lxml")
        # receive_time = int(time.time())
        id_list = []
        for tag in soup.findAll(True, {'id': True}):
            id_list.append(tag['id'])

        # remove normal tags
        id_list = [x for x in id_list if x not in normal_ids]
        if not id_list[0] == 'message_success':
            print ('message send failed! : %s' % id_list[0])
            return 1
        else:
            self.text.insert(END, 'Sent request containing message %s successfully to %s!\n' % (send_msg.rsplit('.', 1)[0]), htor_website)

        my_flags = []
        my_msgs = []
        if len(id_list) == 1:
            self.text.insert(END, 'No message return\n')
        else:

            for index, id in enumerate(id_list[1:]):
                if id in flags:
                    true_msg = str(url2pathname(id_list[index + 2]))
                    my_flags.append(id_list[index + 1])
                    my_msgs.append(true_msg)
            # handle valid msgs friend by friend
            if len(my_flags) == 0:
                self.text.insert(END, '@@@No your message return\n')
            else:
                for friend in frds:
                    msg_findex = frds.index(friend)
                    hash_re = str(friend['received_last'])
                    hash_sl = str(friend['send_last'])
                    #  if not hash_re, not possible to own hash_sl
                    if (not hash_re in my_flags) and (not hash_sl in my_flags):
                        continue
                    #  examine each flag and msg in order and remove it if successfully processed, in order to avoid disorder
                    num = 0
                    length = len(my_flags)
                    while num < length:
                        my_flag = my_flags[num]
                        if hash_re == my_flag or hash_sl == my_flag:
                            my_msg = my_msgs[num]
                            sender = friend['name']
                            print ('received message flag: %s' % my_flag)
                            print ('received message second: %s' % my_msg)
                            try:
                                msg = seccure.decrypt(my_msg, str(friend['my_pr']))
                            except:
                                try:
                                    msg = seccure.decrypt(my_msg, str(friend['last_pr']))
                                except:
                                    print ('Error: decrypt error!')
                                    # means this message is not for you!
                                    num += 1
                                    length = len(my_flags)
                                    continue
                            # if decode successfully, then prove the message is yours.
                            f_pub, htor_msg, sign_msg, send_time = msg[:25], msg[25:75], msg[75:-10], msg[-10:]
                            print ('message decrypt ok, verify using pub %s' % str(url2pathname(friend['pub'])))
                            print ('message decrypt ok, verify using received_pub %s' % str(
                                url2pathname(friend['received_pub'])))
                            print ('htor_msg: %s' % htor_msg)
                            print ('sign_msg: %s' % sign_msg)
                            sig = True if seccure.verify(htor_msg, sign_msg,
                                                         str(url2pathname(friend['pub']))) is True else False
                            if sig is False:
                                sig = True if seccure.verify(htor_msg, sign_msg,
                                                             str(url2pathname(
                                                                 friend['received_pub']))) is True else False
                            if sig is False:
                                print ('Error: verify error!')
                            if sig:
                                self.text.insert(END, '%s  %s: %s\n' % (datetime.datetime.fromtimestamp(float(send_time)).strftime('%Y-%m-%d %H:%M:%S'), sender, htor_msg.rsplit('.', 1)[0]))
                                del my_flags[num]
                                del my_msgs[num]
                                num -= 1
                                #  if a new pub exist
                                if not str(url2pathname(friend['received_pub'])) == f_pub:  # a new pub
                                    frds[msg_findex]['pub'] = str(frds[msg_findex]['received_pub'])
                                    frds[msg_findex]['received_pub'] = pathname2url(f_pub)
                                    print ('update friend %s received_pub to %s ' % (sender, f_pub))
                                    frds[msg_findex]['my_pr'] = str(frds[msg_findex]['last_pr'])
                                    frds[msg_findex]['my_pub'] = str(frds[msg_findex]['last_pub'])
                                    print ('update friend %s last_pr(pub) tp my_pr(pub)' % sender)
                                frds[msg_findex]['last_message'] = hashlib.sha224(str(htor_msg)).hexdigest()
                                print (
                                    'update friend %s last_message from %s to %s' % (
                                    sender, friend['last_message'], htor_msg))
                                frds[msg_findex]['received_last'] = str(frds[msg_findex]['send_last'])
                                print (
                                    'update friend %s received_last : %s' % (sender, str(friend['send_last'])))
                        num += 1
                        length = len(my_flags)
                    update_one_friend(frds[msg_findex])

        # for each in raw_msgs, update their send_last
        frds[findex]['send_last'] = hashlib.sha224(str(send_msg)).hexdigest()
        frds[findex]['received_message'] = str(frds[findex]['last_message'])
        frds[findex]['last_pr'] = new_pr
        frds[findex]['last_pub'] = pathname2url(new_pub)
        update_one_friend(frds[findex])
        return 0

    def send_one_message(self):
        frds = load_all_friends()
        recvr = str(self.sname_entry.get())
        friend = load_one_friend(recvr)
        if friend == 1:
            self.text.insert(END, "Friend %s doesn't exist, please input a correct nickname in your friend list." % recvr)
            return 1
        msg = str(self.smsg_entry.get())
        msg += '.' + ''.join('s' for _ in range(49 - len(msg)))
        all_msgs = []
        if friend['my_pr'] == friend['last_pr']:
            new_pr = set_new_pr()
        else:
            new_pr = str(friend['last_pr'])
        new_pub = str(seccure.passphrase_to_pubkey(new_pr))
        enc_msg = add_single_message(friend, msg, new_pub)
        all_msgs.append(enc_msg)
        # raw_msgs.update(raw)
        # raw_new_prs.update({target: new_pr})
        resp = send_all_messages(all_msgs, '')
        self.handle_all_response(resp.body, load_friends_tags(), frds.index(friend), msg, new_pr, new_pub)

    def click_add_friend(self):
        #   here name is a nickname, only uid and pub is required for adding friends.
        # pub = pathname2url(pub)
        name = str(self.fname_entry.get())
        uid = str(self.fuid_entry.get())
        pub = str(self.fpub_entry.get())
        friend = {
            'name': name,
            'uid': str(uid),
            'last_message': hashlib.sha224(str(user['uid'])).hexdigest(),
            'pub': str(pub),
            'send_last': hashlib.sha224(str(uid)).hexdigest(),
            'received_last': hashlib.sha224(str(uid)).hexdigest(),
            'received_message': hashlib.sha224(str(user['uid'])).hexdigest(),
            'my_pr': str(user['pr']),
            'my_pub': str(user['pub']),
            'last_pr': str(user['pr']),
            'last_pub': str(user['pub']),
            'received_pub': str(pub)
        }
        if not os.path.isfile(folder + name):
            touch(folder + name)
        with open(folder + name, 'w') as f:
            f.write(json.dumps(friend))
        frds = load_all_friends()
        friend_lists = [str(frd['name']) for frd in frds]
        self.friends_str['text'] = "Your friends: %s" % ' '.join(friend_lists)
        return 0

if __name__ == "__main__":
    WidgetsDemo()

