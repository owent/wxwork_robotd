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


## 下载和安装

您可以在 https://github.com/owt5008137/wxwork_robotd/releases 下载预发布包，解压即可。

> 或者使用 rust 的cargo 命令```cargo install wxwork_robotd``` 来直接安装到 ```$HOME/.cargo/bin``` 。
> 这种方式只会安装可执行程序，其他的示例文件和工具脚本可以在 ```$HOME/.cargo/registry/src/github.com-*/wxwork_robotd-*``` 里找到。

发布包文件说明：

1. [etc/conf.json](etc/conf.json) ：示例的配置文件。
2. [etc/firewalld/wxwork_robotd.xml](etc/firewalld/wxwork_robotd.xml) ： 示例的firewalld配置文件。
  > 请先修改端口号为和配置文件保持一致。
  > 然后复制到 ```/etc/firewalld/services/wxwork_robotd.xml``` 后执行 ```sudo firewall-cmd --permanent --add-service=wxwork_robotd``` 即可。

3. [etc/systemd/wxwork_robotd.service](etc/systemd/wxwork_robotd.service) ： 示例的systemd服务配置文件
  > 请先修改部署目录和实际使用的路径保持一致
  > 然后复制到 ```/usr/lib/systemd/system/wxwork_robotd.service``` 后执行 ```sudo systemctl enable wxwork_robotd && sudo systemctl start wxwork_robotd``` 即可。

4. [etc/systemv/wxwork_robotd](etc/systemv/wxwork_robotd) ： 示例的用于 systemv 的服务配置文件
5. [etc/init.d/wxwork_robotd](etc/init.d/wxwork_robotd) ： 示例的用于 init.d 的服务配置文件
6. [tools](tools) ： 用于主动发机器人消息的工具脚本


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
  * WXWORK_ROBOT_IMAGE_URL                  : 如果是图文混排和图片消息，这个指向消息内的图片地址(版本>=0.8.0)
  * WXWORK_ROBOT_GET_CHAT_INFO_URL          : 可以用于获取消息信息的URL(版本>=0.3.9)，有效期为5分钟，调用一次后失效
  * WXWORK_ROBOT_POST_ID                    : post id(版本>=0.9.0)
  * WXWORK_ROBOT_CHAT_ID                    : chat id(版本>=0.3.9)，用于区分聊天群，如果机器人被添加到多个群，可以用这个指定主动发消息到哪个群
  * WXWORK_ROBOT_CHAT_TYPE                  : chat type(版本>=0.6.1)，对应企业微信机器人消息的ChatType字段（会话类型，single/group，分别表示：单聊\群聊话）
  * WXWORK_ROBOT_HTTP_RESPONSE              : HTTP回包(仅 ```type``` 为 http 时的echo字段可用)
  * WXWORK_ROBOT_MSG_TYPE                   : msg type(版本>=0.7.0)，对应企业微信机器人消息的MsgType字段（text/event/attachment）
  * WXWORK_ROBOT_APP_VERSION                : msg type(版本>=0.7.0)，对应企业微信机器人消息的AppVersion字段
  * WXWORK_ROBOT_EVENT_TYPE                 : msg type(版本>=0.7.0)，对应企业微信机器人消息的EventType字段（目前可能是add_to_chat表示被添加进群，或者delete_from_chat表示被移出群, enter_chat 表示用户进入机器人单聊）
  * WXWORK_ROBOT_ACTION_NAME                : msg type(版本>=0.7.0)，对应企业微信机器人消息的Actions.Name字段（用户点击按钮的名字）
  * WXWORK_ROBOT_ACTION_VALUE               : msg type(版本>=0.7.0)，对应企业微信机器人消息的Actions.Value字段（用户点击按钮的值）
  * WXWORK_ROBOT_ACTION_CALLBACKID          : msg type(版本>=0.7.0)，对应企业微信机器人消息的Attachment.CallbackId字段（attachment中设置的回调id）


## 配置说明

注意，下面只是配置示例，实际使用的配置必须是标准json，不支持注释

```javascript
{
    "listen": ["0.0.0.0:12019", ":::12019"], // 监听列表，这里配置了ipv4和ipv6地址
    "task_timeout": 4000,                    // 超时时间4000ms，企业微信要求在5秒内回应，这里容忍1秒钟的网络延迟
    "workers": 8,                            // 工作线程数
    "backlog": 256,                          // 建立连接的排队长度
    "keep_alive": 5,                         // tcp保持连接的心跳间隔（秒） (版本: >=0.6.0)
    "client_timeout": 5000,                  // 客户端第一个请求的超时时间（毫秒） (版本: >=0.6.0)
    "client_shutdown": 5000,                 // 客户端连接的超时时间（毫秒） (版本: >=0.6.0)
    "max_connection_per_worker": 20480,      // 每个worker的最大连接数，当连接数满之后不会再接受新连接 (版本: >=0.6.0)
    "max_concurrent_rate_per_worker": 256,   // 每个worker的最大握手连接数，当连接数满之后不会再接受新连接（一般用于控制SSL握手的开销） (版本: >=0.6.0)
    "payload_size_limit": 262144,            // 消息体最大长度，默认: 262144(256KB) (版本: >=0.6.0)
    "cmds": {                                // 这里所有的command所有的project共享
        "default": {                         // 如果找不到命令，会尝试找名称为default的命令执行，这时候
            "type": "echo",                  // 直接输出类型的命令
            "echo": "我还不认识这个指令呐!({{WXWORK_ROBOT_CMD}})", // 输出内容
            "order": 999,                    // 命令匹配优先级，越小则越优先匹配，默认为 0
            "hidden": true                   // 是否隐藏，所有的命令都有这个选项，用户help命令隐藏这条指令的帮助信息
        },
        "": {                               // 如果输入了空消息或者attachment消息，则会匹配这个命令而不是default,没有配置空命令则会直接忽略输入
            "type": "echo",
            "echo": "Hello, 本群会话ID: {{WXWORK_ROBOT_CHAT_ID}}",
            "order": 999,
            "hidden": true
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
            "dot_matches_new_line": false,     // [所有命令] .是否匹配换行符（默认:true）
            "order": 0                         // [所有命令] 命令匹配优先级，越小则越优先匹配(默认: 0)
        },
        "说\\s*(?P<MSG>[^\\r\\n]+)": {
            "type": "echo",
            "echo": "{{WXWORK_ROBOT_CMD_MSG}}", // 可以使用匹配式里的变量
            "description": "说**消息内容**",
            "order": 2
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
            "output_type": "输出类型",          // markdown/text
            "order": 2
        }
    },
    "events": {                                                             // 这里的事件所有project共享
        "add_to_chat": {                                                    // 加入群聊（内容和命令一样）
            "type": "echo",
            "echo": "Hi, 大家好"
        },
        "enter_chat": {                                                     // 加入单聊（内容和命令一样）
            "type": "echo",
            "echo": "Hi, {{WXWORK_ROBOT_MSG_FROM_NAME}}"
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
        },
        "events": {                                                           // 这里的事件仅当前project有效
            "delete_from_chat": {                                             // 离开群聊
                "type": "echo",
                "echo": "再见"
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
5. 运行编译命令: ```cargo build```

更多详情见： https://rustup.rs/ 

## LICENSE

[MIT](LICENSE-MIT) or [Apache License - 2.0](LICENSE)

[1]: https://crates.io/crates/handlebars
[2]: https://docs.rs/regex/
