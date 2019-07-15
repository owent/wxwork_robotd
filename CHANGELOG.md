CHANGELOG
============

0.6.0
----------

1. 更新 [actix-web][1] 更新到新的大版本(^1.0.3)
2. 增加超时时间控制
3. 增加可自定义的消息Body大小配置
4. 增加可自定义连接数的配置
5. 移除对原来 [base64](https://crates.io/crates/base64) 模块的依赖（有BUG，这么高下载量的库实现都有BUG，rust生态真的不太行），改为自己实现的base64算法
6. 增加访问HTTPS的支持

[1]: https://actix.rs/