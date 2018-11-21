# 企业微信机器人接入

来自企业微信机器人的请求会先按填入的URL的最后一节匹配到配置中 ```projects``` 里 ```name``` 对应的项目中，然后优先从 ```projects``` 内尝试匹配命令，再从全局域匹配命令。 命令的类型( ```type``` )支持 **echo （输出消息）** 、 **http （HTTP请求）** 和 **spawn （子进程执行命令）** 。 配置项中的 *echo* 、 *exec* 、 *args* 、 *url* 、 *post* 会使用模板引擎尝试对内容进行替换（传参），传入的参数可以是匹配命令里的匹配结果，也可以是预先配置好的环境变量。

如果是 **spawn （子进程执行命令）** 类型的请求，配置里的环境变量在子进程中也可用。

## 环境变量命名

+ CMD和匹配的内容可以通过 ```{{WXWORK_ROBOT_CMD}}``` 和 ```{{WXWORK_ROBOT_CMD_<变量名或匹配名\>}}``` 来获取。
+ ```projects``` 中的内容可以通过 ```{{WXWORK_ROBOT_PROJECT_<变量名或匹配名\>}}``` 来获取。
+ 环境变量只会导出类型为字符串、数字或者布尔值的内容，不支持嵌套内容

## 语法相关

+ 完整示例配置见 [etc/conf.json](etc/conf.json)
+ 配置参数模板语法见: [handlebars][1]
+ 正则表示语法见: [regex][2]

[1]: https://crates.io/crates/handlebars
[2]: https://docs.rs/regex/