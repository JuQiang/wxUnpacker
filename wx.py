from Crypto.Cipher import AES
import hashlib
import os
import json
import urllib
import jsbeautifier
import execjs
import argparse
import os

# 微信小程序文件格式
# 文件头
# 1字节 一定是190
# 4字节 一定是0
# 4字节 索引段长度
# 4字节 数据段长度
# 1字节 一定是237
# 4字节 文件总个数
# 索引段
# 4字节 文件名长度
# N字节 文件名
# 4字节 文件在数据段中的位置（相对于header的0偏移，而不是如下数据段的0偏移）
# 4字节 文件长度
# 数据段

# 1、先把mac os的SIP做一个disable or enable SIP，否则lldb不能attach到wechat进程上。
# 2、打开wechat，但是不登录。
# 3、lldb -p wechat的pid。
# 4、br set -n sqlite3_key，断点设置好后，c继续运行。
# 5、微信登录后，会break到断点上，输入memory read --size 1 --format x --count 32 $rsi
# 6、前16位即是你本机的wechat小程序加密的密钥，而完整的32位则是本机微信聊天记录sqlite db的密钥。

OUTPUT_FOLDER = "output"
NEED_BEAUTIFY_JS = False


global_wxml = ["",0]


def get_string_by_seperators(source, begin_str, end_str, begin_index):
    index = source.find(begin_str, begin_index)
    if index == -1:
        return "", -1

    index2 = source.find(end_str, index + len(begin_str))
    if index2 == -1:
        return "", -1

    return source[index + len(begin_str):index2], index2 + len(end_str)

def decrypt(buf, wxid, local_mac_package_key):
    seek = 0 if len(local_mac_package_key)==16 else 6

    wx_header = buf[seek:seek+1024]
    wx_others = buf[seek+1024:]

    if len(local_mac_package_key)==16:
        cipher = AES.new(local_mac_package_key, AES.MODE_ECB)
        decrypted_wx_header = cipher.decrypt(wx_header)

        return decrypted_wx_header + wx_others
    else:
        aes_key = hashlib.pbkdf2_hmac('sha1', wxid.encode(), b"saltiest", 1000, 32)
        cipher = AES.new(aes_key,AES.MODE_CBC,b"the iv: 16 bytes")

        decrypted_wx_header = cipher.decrypt(wx_header)
        n = decrypted_wx_header[-1]
        if n > 0:
            decrypted_wx_header = decrypted_wx_header[:-n]

        xor_key = ord(str(wxid[-2]))
        decrypted_wx_others = []
        for b in wx_others:
            decrypted_wx_others.append(b ^ xor_key)

        return decrypted_wx_header + bytes(decrypted_wx_others)

def write_file(fname, buf, mode):
    items = fname.split("/")
    path = OUTPUT_FOLDER
    for i in range(0, len(items) - 1):
        path += "/" + items[i]
        md(path)

    f = open(path + "/" + items[-1], mode)
    f.write(buf)
    f.close()

def process_package(buf):
    index = 0
    # <editor-fold desc="处理微信头">
    print("magic number is " + str(ord(buf[index:1])))
    index += 1
    print("always o is {0}".format(int.from_bytes(buf[index:index + 4], "big")))
    index += 4
    index_seg_length = int.from_bytes(buf[index:index + 4], "big")
    print("index segments length is {0}".format(index_seg_length))
    index += 4
    body_seg_length = int.from_bytes(buf[index:index + 4], "big")
    print("body segments length is {0}".format(body_seg_length))
    index += 4
    print("last mask must be 237 ---> {0}".format(int.from_bytes(buf[index:index + 1], "big")))
    index += 1
    file_count = int.from_bytes(buf[index:index + 4], "big")
    print("file count is {0}".format(file_count))
    index += 4
    # </editor-fold">

    index_length = 0
    # <editor-fold desc="处理微信数据段">
    for fcount in range(0, file_count):
        if index_length + 4 >= index_seg_length:  # 如果用while true
            break
        filename_length = int.from_bytes(buf[index:index + 4], "big")
        index += 4
        fname = buf[index:index + filename_length].decode()
        index += filename_length
        offset_of_file_in_segment = int.from_bytes(buf[index:index + 4], "big")
        index += 4
        file_size = int.from_bytes(buf[index:index + 4], "big")
        index += 4

        print("File name length ={0}, file name = {1}, offset in segment = {2}, file size = {3}".format(filename_length,
                                                                                                        fname,
                                                                                                        offset_of_file_in_segment,
                                                                                                        file_size))

        content = buf[offset_of_file_in_segment:offset_of_file_in_segment + file_size]
        if fname.endswith(".json"):
            content = urllib.parse.unquote(json.dumps(json.loads(content.decode()), indent=4))
            write_file(fname, content, "w")
        elif fname.endswith(".js"):
            content = content.decode()
            if "app-service.js" not in fname and NEED_BEAUTIFY_JS is True:
                content = jsbeautifier.beautify(content)
            write_file(fname, content, "w")
        else:
            write_file(fname, content, "wb")
        index_length += 4 * 3 + filename_length
    # </editor-fold>

def md(dir):
    if os.path.exists(dir) is False:
        os.mkdir(dir)

def process_json(fname):
    if os.path.exists(fname) is False:
        return

    f = open(fname, "r")
    all_lines = f.readlines()
    f.close()

    token = ".json'] = {"
    jsons = ''.join(all_lines).split("__wxAppCode__[")

    for j in jsons:
        if token in j:
            index = j.index(token)
            fname = j[1:index] + ".json"
            print("Processing " + fname)
            content, index = get_string_by_seperators(j[index + len(token) - 1:], "{", "};", 0)
            content = json.dumps(json.loads("{" + content + "}"), indent=4)
            write_file(fname, content, "w")

def process_js(js_file):
    fname = OUTPUT_FOLDER + "/" + js_file
    if os.path.exists(js_file) is False:
        return

    f = open(js_file, "r")
    all_lines = f.readlines()
    f.close()

    items = ''.join(all_lines).split('define("')
    for i in range(1,len(items)):
        line = items[i]
        index = line.index(",")
        fname = line[0:index].replace('"','')

        index = line.index("{")
        line = line[index+1:].strip()

        index = line.rindex("});")
        line = line[0:index]

        if "}" in line:
            index = line.rindex("}")
            line = line[0:index]

        if line.startswith("'use strict';") or line.startswith('"use strict";'):
            line = line[13:]
        elif (line.startswith('(function(){"use strict";') or line.startswith(
                "(function(){'use strict';")) and line.endswith("})();"):
            line = line[25:][:-5]

        print("Processing " + fname)
        if NEED_BEAUTIFY_JS:
            write_file(fname, jsbeautifier.beautify(line), "w")
        else:
            write_file(fname, line, "w")

def process_wxss(fname):
    fname = OUTPUT_FOLDER + "/"+fname
    if os.path.exists(fname) is False:
        return

    f = open(fname, "r")
    all_lines = f.readlines()
    f.close()

    token = ".wxss"
    jsons = ''.join(all_lines).split("setCssToHead(")

    for j in jsons:
        if token in j:
            index = j.find('",],', 0)
            if index == -1:
                continue
            buf = j[0:index] + ";}"
            content = buf[:-2].replace('",[1],"', '').replace("\\n", '\n')
            items = content.split("\n")

            content = ""
            for item in items:
                if item == ";}":
                    continue
                if item.startswith('["'):
                    item = item[2:]
                c2 = item.replace("{", " {\n\t").replace(";", ";\n\t").replace("}", "\n}\n\n").replace("\\x3d",
                                                                                                       "=").replace(
                    "\\x22", '"').replace('",[0,', "").replace('],"', 'px').replace(":", ": ").replace("wx-", "")
                c3 = c2.replace("\n}\n\n", ";\n}\n\n")
                if c3.startswith(";"):
                    c3 = c3[1:]
                content += c3

            fname = get_string_by_seperators(j, ',{path:"', '"})', 0)[0].replace("./", "")
            print("Processing " + fname)
            write_file(fname, content.replace("body {", "page {").replace(": : ", "::"), "w")

def process_wxml_nodes(nodes):
    wxml = ""
    if global_wxml[1]>0:
        wxml = "\t"*global_wxml[1]

    if type(nodes).__name__ != "dict":
        global_wxml[0] += str(nodes)
        return

    tag = nodes["tag"].replace("wx-", "")
    wxml += "<" + tag

    if nodes.get("attr") is not None:
        for attr in nodes["attr"].keys():
            wxml += " " + attr + "=\"" + str(nodes["attr"][attr]) + "\""
    wxml += ">"
    wxml += "\n"

    global_wxml[0] += wxml

    global_wxml[1] += 1
    for child in nodes["children"]:
        process_wxml_nodes(child)
    global_wxml[1] -= 1

    global_wxml[0] += "</" + tag + ">\n"

    return

def process_wxml_remove_useless(wxml_source):
    source = wxml_source

    tmp = get_string_by_seperators(wxml_source,"<script>","</script>",0)[0]
    if len(tmp)>0:
        index = tmp.find("var setCssToHead")
        index2 = tmp.rindex(");")
        source = tmp[0:index]+tmp[index2+2:]

    else:
        first_token = 'if (!noCss)'
        last_token = 'var __subPageFrameEndTime__ = Date.now();'
        index = wxml_source.find(first_token)
        index2 = wxml_source.find(last_token, index)

        if index>-1 and index2>-1:
            source = wxml_source[0:index] + wxml_source[index2:]

    return source

def process_wxml(pageframe):
    pageframe = OUTPUT_FOLDER + "/" + pageframe
    if os.path.exists(pageframe) is False:
        return

    source = open(pageframe).read()
    if source=="/* This file is left intentionally blank */":
        return

    flist = "\n"
    patch = 'var window={};var navigator={};navigator.userAgent="iPhone";window.screen={};document={};function define(){};function require(){};function setCssToHead(file, _xcInvalid, info){};'

    items = source.split("else __wxAppCode__[")
    x = []
    index = 0
    for item in items:
        func = get_string_by_seperators(item,"=",";",0)[0]
        if "$" not in func:
            continue
        flist += "fuck_{0}={1};\n".format(index,func.strip())
        index+=1
        x.append(get_string_by_seperators(item,"'","'",0)[0])

    source = process_wxml_remove_useless(source)
    patched_source = patch + source + flist

    js = execjs.compile(patched_source)


    for func_no in range(0, len(x)):
        try:
            nodes = js.call("fuck_{0}".format(func_no),[],[],[],[])
        except Exception as e:
            print(e)
            continue

        fname = x[func_no].replace("./", "")

        print("Processing "+fname)
        if len(nodes["children"])==0:
            continue
        global global_wxml
        process_wxml_nodes(nodes["children"][0])
        write_file(fname,global_wxml[0],"w")

        global_wxml = ["",0]

def process(flist,func):
    for f in flist:
        func(OUTPUT_FOLDER + f)

        with open(OUTPUT_FOLDER + "/app.json", "r") as fs:
            j = json.load(fs)
            for sub in j["subPackages"]:
                func(OUTPUT_FOLDER + "/" + sub["root"] + f)

def get_package_content(wx_package, wxid,local_mac_package_key):
    fsize = os.path.getsize(wx_package)

    f = open(wx_package, "rb")
    buf = f.read(fsize)
    f.close()

    if int(buf[0]) != 190: # or (buf[0]==b"V" and buf[1]==b"1" and buf[2]==b"M" and buf[3]==b"M" and buf[4]==b"W" and buf[5]==b"X"):
        buf = decrypt(buf, wxid,local_mac_package_key)

    if int(buf[0]) != 190:
        buf = None

    return buf

def init():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", help="Wechat mini program ID.")
    parser.add_argument("-i", help="A <folder name> which contains multiple wxapkg files, or a single wxapkg <file name>.")
    parser.add_argument("-o", help="Output folder.")
    parser.add_argument("-b",default=False, help="True/False means whether to beautify the JS code, True will result in a poor performance.")
    parser.add_argument("-m",default="", help="A 16-bytes local MAC package key. Looks like '00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF'")

    args = parser.parse_args()

    global OUTPUT_FOLDER
    OUTPUT_FOLDER = args.o
    if args.o is None:
        OUTPUT_FOLDER = "output"

    global NEED_BEAUTIFY_JS
    NEED_BEAUTIFY_JS = args.b


    wxid = args.w
    input = args.i
    local_mac_package_key = bytes.fromhex(args.m)

    wxapkg = []

    if input is None:
        input = "."

    if ".wxapkg" in input and os.path.exists(input):
        wxapkg.append(input)
    elif os.path.exists(input):
        for fp,dirs,fs in os.walk(input):
            for f in fs:
                if ".wxapkg" in f:
                    wxapkg.append(os.path.join(fp,f))

    return wxid,wxapkg,local_mac_package_key

def main():
    wxid, wxapkg,local_mac_package_key = init()
    if wxid is None or len(wxapkg)==0:
        print("Error wxid or input files. Type < python3 wx.py --help > to get more information.")
        return

    md(OUTPUT_FOLDER)

    print("Unpacking package...")
    for apkg in wxapkg:
        buf = get_package_content(apkg,wxid,local_mac_package_key)
        if buf is not None:
            process_package(buf)

    print("================================================================")
    print("")
    print("Unpacking JSON files...")
    process_json(OUTPUT_FOLDER+"/app-service.js")

    print("================================================================")
    print("")
    print("Unpacking JS files...")
    process(["/app-service.js"], process_js)


    print("================================================================")
    print("")
    print("Unpacking WXSS files...")
    process(["/page-frame.js", "/page-frame.html"], process_wxss)

    print("================================================================")
    print("")
    print("Unpacking WXML files...")
    process(["/app-service.js", "/page-frame.js", "/page-frame.html"], process_wxml)

if __name__ == "__main__":
    main()
