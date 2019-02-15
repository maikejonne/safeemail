# An implementation based on secure mail protocol
## 简介
这是“安全数据通讯协议”的服务器，基于NodeBB插件模式的快速实现。

SMTP(Simple Mail Transfer Protocol)即简单邮件传输协议，它是一组用于由源地址到目的地址传送邮件的规则,由它来控制信件的中转方式。是为不同服务提供商辖属的用户提供信息交互的一种方案。但它数据可被恶意篡改或伪造的，用户信息是可被攻击的，且存在有大量的垃圾信息。

SDTP(Safe Date Transfer Protocol)即“安全数据通讯协议”它为不同服务提供商辖属的用户提供了安全的、隐私保护的、高效的数据交换方式。

一、SDTP的用户认证体系是基于零知识证明的数字签名，所以
1、SDTP不会产生垃圾邮件信息。
2、用户的邮件信息不会被黑客或者服务提供商恶意篡改与伪造。

二、SDTP的数据传输模式亦是基于零知识证明的，消息互动双方是隐私保护的。
1、发送邮件时，邮件服务商只知道有邮件信息需要发送，但无法获悉接收人信息。
2、邮件被送达时，邮件服务商只知道接收人是谁，但无法获悉该邮件的发送人信息。

三、SDTP的通讯数据被攻击时，例如服务商恶意拒绝服务或黑客消息拦截，会留下轨迹的并会通知用户的。SDTP的服务商是多中心化的，这有点类似比特币中的记账人机制，除非所有可能的获得记账权的记账人都不给某个地址提供转账服务。

## 安装

    cd NodeBB
    git clone https://github.com/maikejonne/safeemail nodebb-plugin-semail
    npm install ./nodebb-plugin-semail
打开NodeBB的Plugin页面, 找到

![未安装][1]

点击Active

![已安装][2]
## API
[API描述][3]


  [1]: https://raw.githubusercontent.com/maikejonne/safeemail/master/docs/unactive.png
  [2]: https://raw.githubusercontent.com/maikejonne/safeemail/master/docs/active.png
  [3]: https://maikejonne.github.io/safeemail/