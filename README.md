# 企业微信机器人接入

|                           | [Linux+OSX][linux-link] | [Windows MSVC+GNU][windows-link] |
|:-------------------------:|:-----------------------:|:--------------------------------:|
| Build & Publish           | ![linux-badge]          | ![windows-badge]                 |

[linux-badge]: https://travis-ci.org/owt5008137/wxwork_robotd.svg?branch=master "Travis build status"
[linux-link]:  https://travis-ci.org/owt5008137/wxwork_robotd "Travis build status"
[windows-badge]: https://ci.appveyor.com/api/projects/status/ht5pks682ehe2vkt?svg=true "AppVeyor build status"
[windows-link]:  https://ci.appveyor.com/project/owt5008137/wxwork-robotd "AppVeyor build status"

来自企业微信机器人的请求会先按填入的URL的最后一节匹配到配置中 ```projects``` 里 ```name``` 对应的项目中，然后优先从 ```projects``` 内尝试匹配命令，再从全局域匹配命令。 命令的类型( ```type``` )支持 **echo （输出消息）** 、 **http （HTTP请求）** 、 **help （帮助信息）** 和 **spawn （子进程执行命令）** 。 配置项中的 *echo* 、 *exec* 、 *args* 、 *url* 、 *post* 、 *prefix* 、 *suffix* 会使用模板引擎尝试对内容进行替换（传参），传入的参数可以是匹配命令里的匹配结果，也可以是预先配置好的环境变量。

如果是 **spawn （子进程执行命令）** 类型的请求，配置里的环境变量在子进程中也可用。

可以通过 ```./wxwork_robotd -h``` 查看可用选项。[etc](etc) 目录里有各种系统的启动脚本模板。


## 主动发消息接口

[tools](tools) 目录包含用于主动发消息的**企业微信机器人脚本**，兼容 python 2.7-3.X 。 

> python 2.7 依赖 [requests](https://pypi.org/project/requests/)库。 可通过 ```pip install requests``` 来安装。

## 环境变量命名

+ CMD和匹配的内容可以通过 ```{{WXWORK_ROBOT_CMD}}``` 和 ```{{WXWORK_ROBOT_CMD_<变量名或匹配名>}}``` 来获取。
+ ```projects``` 中的内容可以通过 ```{{WXWORK_ROBOT_PROJECT_<变量名或匹配名>}}``` 来获取。
+ 环境变量只会导出类型为字符串、数字或者布尔值的内容，不支持嵌套内容
+ 可用的环境变量
  * WXWORK_ROBOT_WEBHOOK_KEY                : 当前消息对应机器人的WebhookURL里的key字段(可用来回发消息,版本>=0.3.3)
  * WXWORK_ROBOT_WEBHOOK_URL                : 当前消息对应机器人的WebhookURL(可用来回发消息,版本>=0.3.3)
  * WXWORK_ROBOT_CMD                        : 当前执行命令的完整匹配消息
  * WXWORK_ROBOT_CMD_{VARNAME}              : 当前执行命令的匹配参数（必须是命名匹配式）或配置的环境变量
  * WXWORK_ROBOT_PROJECT_NAME               : 配置的项目名
  * WXWORK_ROBOT_PROJECT_TOKEN              : 配置的项目验证token
  * WXWORK_ROBOT_PROJECT_ENCODING_AES_KEY   : 配置的项目base64的aes key
  * WXWORK_ROBOT_PROJECT_{VARNAME}          : 配置的项目中的环境变量
  * WXWORK_ROBOT_MSG_FROM_USER_ID           : 发消息者的用户id(版本>=0.3.6)
  * WXWORK_ROBOT_MSG_FROM_NAME              : 发消息者的用户名称(版本>=0.3.6)
  * WXWORK_ROBOT_MSG_FROM_ALIAS             : 发消息者的用户别名(版本>=0.3.6)
  * WXWORK_ROBOT_MSG_ID                     : 消息ID(版本>=0.3.6)
  * WXWORK_ROBOT_GET_CHAT_INFO_URL          : 可以用于获取消息信息的URL(版本>=0.3.9)，有效期为5分钟，调用一次后失效
  * WXWORK_ROBOT_CHAT_ID                    : chat id(版本>=0.3.9)，用于区分聊天群，如果机器人被添加到多个群，可以用这个指定主动发消息到哪个群
  * WXWORK_ROBOT_HTTP_RESPONSE              : HTTP回包(仅 ```type``` 为 http 时的echo字段可用)


## 配置说明

注意，下面只是配置示例，实际使用的配置必须是标准json，不支持注释

```javascript
{
    "listen": ["0.0.0.0:12019", ":::12019"], // 监听列表，这里配置了ipv4和ipv6地址
    "taskTimeout": 4000,                     // 超时时间4000ms，企业微信要求在5秒内回应，这里容忍1秒钟的网络延迟
    "workers": 8,                            // 工作线程数
    "backlog": 256,                          // 建立连接的排队长度
    "keep_alive": 5,                         // tcp保持连接的心跳间隔（秒）
    "client_timeout": 5000,                  // 客户端第一个请求的超时时间（毫秒）
    "client_shutdown": 5000,                 // 客户端连接的超时时间（毫秒）
    "max_connection_per_worker": 20480,      // 每个worker的最大连接数，当连接数满之后不会再接受新连接
    "max_concurrent_rate_per_worker": 256,   // 每个worker的最大握手连接数，当连接数满之后不会再接受新连接（一般用于控制SSL握手的开销）
    "cmds": {                                // 这里所有的command所有的project共享
        "default": {                         // 如果找不到命令，会尝试找名称为default的命令执行，这时候
            "type": "echo",                  // 直接输出类型的命令
            "echo": "我还不认识这个指令呐!({{WXWORK_ROBOT_CMD}})", // 输出内容
            "hidden": true                   // 是否隐藏，所有的命令都有这个选项，用户help命令隐藏这条指令的帮助信息
        },
        "(help)|(帮助)|(指令列表)": {
            "type": "help",                    // 帮助类型的命令
            "description": "help|帮助|指令列表", // 描述，所有的命令都有这个选项，用于help类型命令的输出，如果没有这一项，则会直接输出命令的key（匹配式）
            "prefix": "### 可用指令列表\r\n"     // 帮助信息前缀
            "suffix": ""                       // 帮助信息后缀
            "case_insensitive": true,          // [所有命令] 是否忽略大小写（默认:true）
            "multi_line": true,                // [所有命令] 是否开启逐行匹配（默认:true，When enabled, ^ matches the beginning of lines and $ matches the end of lines.）
            "unicode": true,                   // [所有命令] 是否开启unicode支持（默认:true，When disabled, character classes such as \w only match ASCII word characters instead of all Unicode word characters）
            "octal": true,                     // [所有命令] 是否支持octal语法（默认:false）
            "dot_matches_new_line": false      // [所有命令] .是否匹配换行符（默认:true）
        },
        "说\\s*(?P<MSG>[^\\r\\n]+)": {
            "type": "echo",
            "echo": "{{WXWORK_ROBOT_CMD_MSG}}", // 可以使用匹配式里的变量
            "description": "说**消息内容**"
        },
        "执行命令\\s*(?P<EXEC>[^\\s]+)\\s*(?P<PARAM>[^\\s]*)": {
            "type": "spawn",                    // 启动子进程执行命令，注意，任务超时并不会被kill掉
            "exec": "{{WXWORK_ROBOT_CMD_EXEC}}",
            "args": ["{{WXWORK_ROBOT_CMD_PARAM}}"],
            "cwd": "",
            "env": {                            // 命令级环境变量，所有的命令都有这个选项，这些环境变量仅此命令有效
                "TEST_ENV": "all env key will be WXWORK_ROBOT_CMD_{NAME IN ENV} or WXWORK_ROBOT_PROJECT_{NAME}"
            },
            "description": "执行命令**可执行文件路径** ***参数***",
            "output_type": "输出类型"            // markdown/text
        }
    },
    "projects": [{                                                          // 项目列表，可以每个项目对应一个机器人，也可以多个机器人共享一个项目
        "name": "test_proj",                                                // 名称，影响机器人回调路径，比如说这里的配置就是: http://外网IP:/12019/test_proj/
        "token": "hJqcu3uJ9Tn2gXPmxx2w9kkCkCE2EPYo",                        // 对应机器人里配置的Token
        "encodingAESKey": "6qkdMrq68nTKduznJYO1A37W2oEgpkMUvkttRToqhUt",    // 对应机器人里配置的EncodingAESKey
        "env": {                                                            // 项目级环境变量，这些环境变量仅此项目有效
            "testURL": "robots.txt"
        },
        "cmds": {                                                           // 项目级命令，这些命令仅此项目有效
            "http请求": {
                "type": "http",                                             // http请求类命令
                "method": "get",                                            // http方法，可选值为 get/post/put/delete/head，如果不填则会自动从设置，如果post里有数据则会自动设为post，否则自动设为get
                "url": "https://owent.net/{{WXWORK_ROBOT_PROJECT_TEST_URL}}", // http请求地址
                "post": "",                                                   // body里的数据
                "content_type": "",                                           // content-type，可不填
                "headers": {                                                  // 请求的额外header
                    "X-TEST": "value"
                },
                "echo": "已发起HTTP请求，回包内容\r\n{{WXWORK_ROBOT_HTTP_RESPONSE}}" // 机器人回应内容
            },
            "访问\\s*(?P<URL>[^\\r\\n]+)": {
                "type": "http",
                "url": "{{WXWORK_ROBOT_CMD_URL}}",
                "post": "",
                "echo": "HTTP请求: {{WXWORK_ROBOT_CMD_URL}}\r\n{{WXWORK_ROBOT_HTTP_RESPONSE}}",
                "description": "访问**URL地址**"
            }
        }
    }]
}
```

## 语法相关

+ 完整示例配置见 [etc/conf.json](etc/conf.json)
    > 请确保 taskTimeout 字段低于5000毫秒，因为企业微信的超时是5秒，如果加上网络延迟之后机器人回包略多于5s企业微信会无回包

+ 配置参数模板语法见: [handlebars][1]
+ 正则表示语法见: [regex][2]

## Developer

1. 下载rust编译环境( https://www.rust-lang.org )
    > 在一些发行版或者软件仓库中也可以通过 pacman/apt/yum/choco 等安装 rust 目标
2. 升级rust工具链 ```rustup self update && rustup update```
3. 安装一个编译目标（默认也会安装一个的） ```rustup target install <目标架构>```
    > 可以通过 ```rustup target list``` 来查看支持的架构
4. 克隆仓库并进入主目录
5. 如果是Windows环境，需要准备openssl开发包，并通过环境变量 ```OPENSSL_DIR``` 来指定安装包。(其他环境可略过这步)
    > 可以从 http://slproweb.com/products/Win32OpenSSL.html 下载预编译包，必须用完整版，不能用Light版本
6. 运行编译命令: ```cargo build```

更多详情见： https://rustup.rs/ 

[1]: https://crates.io/crates/handlebars
[2]: https://docs.rs/regex/