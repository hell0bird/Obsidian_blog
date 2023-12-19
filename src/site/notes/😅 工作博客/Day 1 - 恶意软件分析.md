---
{"dg-publish":true,"permalink":"/😅 工作博客/Day 1 - 恶意软件分析/","dgPassFrontmatter":true,"created":"2023-12-19T16:09:17.370+08:00"}
---

恶意软件分析是了解恶意软件工作原理以及如何检测和预防的工作。 虽然我还没有深入到恶意软件的深层次，例如逆向工程，但我有机会探索基本的恶意软件分析。 我希望我的分享能够帮助那些想要迈出恶意软件分析第一步的人。

基本的恶意软件分析包括静态分析和动态分析，正如我在下面的红线中强调的那样： 
![image](https://tsec-weekly.oss-cn-beijing.aliyuncs.com/weekly/202312191609268.png)

> 如何开始学习恶意软件分析 | SANS

# 参考资料

* **[如何开始学习恶意软件分析 | SANS研究所](https://www.sans.org/blog/how-you-can-start-learning-malware-analysis/)
* **[Practical Malware Analysis Essentials for Incident Responders](https://www.youtube.com/watch?v=20xYpxe8mBg&feature=emb_title)

# 分析技巧

分析人员在恶意软件分析过程中需要调查几个要点。 这里有一些对于分析非常有效的技巧。

|静态分析|备注|
|---|---|
|文件类型|检查文件的魔幻数字（magic number），例如"MZ"开头的文件表示.exe的文件|
|壳检查|检查加壳——攻击者使用UPX、MEW等压缩来混淆PE文件。|
|时间戳|检查PE文件何时被编译。|
|Hash值|通过文件的MD5, SHA1, SHA256与威胁狩猎的IOC对比。|
|Dll (动态链接库)|Dll 和 Function 可帮助恶意软件分析人员识别 PE 文件具有哪些功能。|
|功能(Imports / Exports)|Dll 和 Function 可帮助恶意软件分析人员识别 PE 文件具有哪些功能。|
|字符串|查找/获取了解 PE 文件的提示，例如 IP、URL、路径、Dll、函数等。|

|动态分析|备注|
|---|---|
|网络痕迹分析|在静态分析阶段，您可以从字符串值中获取一些与网络活动相关的线索。 例如，您可以使用 Wireshark 跟踪 **HTTP(80)、DNS(53) 等网络活动，甚至过滤某些 URL 关键字**。|
|主机痕迹分析|在静态分析阶段，您可以从字符串值中获得一些与主机活动相关的线索 - **PE文件、进程、命令、路径等。**这些都是动态分析中非常宝贵的关键。 例如，跟踪 PE 文件基于时间线的活动。 监控进程树等PE文件的关系。 通过暂停和恢复流程来一一确认活动。 或者甚至比较恶意软件执行前后的注册表项活动。|

# 分析工具

在基本的静态/动态恶意软件分析过程中，我通常使用这些工具：

### 静态分析

■ Pestudio ([https://www.winitor.com/download](https://www.winitor.com/download))

■ VirusTotal ([https://www.virustotal.com/gui/home/upload](https://www.virustotal.com/gui/home/upload))

■ floss ([https://github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss))

■ MalAPI.io ([https://malapi.io/](https://malapi.io/))

### 动态分析

■ Wireshark ([https://www.wireshark.org/download.html](https://www.wireshark.org/download.html))

■ TCPView ([https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview))

■ Process Monitor ([https://learn.microsoft.com/en-us/sysinternals/downloads/procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon))

■ Process Explorer ([https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer))

■ Process Hacker ([https://processhacker.sourceforge.io/](https://processhacker.sourceforge.io/))

■ regshot ([https://sourceforge.net/projects/regshot/](https://sourceforge.net/projects/regshot/))

# 恶意软件样本

■ [theZoo - A Live Malware Repository](https://github.com/ytisf/theZoo)