# 系统架构

                  SCE, phpAdmin
                     |
                     |
                     |
                     v
           +---------------------+                +---------------------+
           |                     |                |                     |
           | LXC                 |                | LXC                 |
           |                     |                |                     |
           |      WVIP RVIP      |                |                     |
           |       |    |        |                |                     |
           |       |    |        |                |                     |
           |       v    v        |                |                     |
           |    +----------+     |   keepalived   |    +----------+     |
           |    | proxy    |<------------------------->| proxy    |     |
           |    +----------+     |                |    +----------+     |
           |         |  |        |                |     standby         |
           |      rw |  | ro     |                |                     |
           |         |  +-----------------------------------+           |
           |         |           |                |         |           |
           |         v           |                |         v           |
           |    +----------+     |                |    +----------+     |
           |    | mysql    |     |      M-M       |    | mysql    |     |
           |    |          |<------------------------->| ro       |     |
           |    +----------+     |  replication   |    +----------+     |
           |                     |   semi-sync    |                     |
           |                     |                |                     |
           +---------------------+                +---------------------+

             host1                                  host2



功能实现：

* keepalived: dbproxy 高可用、虚IP切换、配置文件同步
* dbproxy: 负载均衡、从库切换。提供操作主库切换的接口（针对于手工切换方案）；或主动进行主库的切换（对于自动切换方案）
* mysql: 一主一从复制 半同步

#如何安装
1 在2台主机配置好mysql主从复杂（半同步）

2 在2台主机配置好dbproxy

3 在2台主机配置好keepalived,配置和脚本均在/etc/keepalived目录下

   * /etc/keepalived配置包括keepalived.conf和haconf(通过haconf可以定义维护模式等)
   * /etc/keepalived也包括keepalived目录下的脚本

# 实现及上线情况

采用高可用方案二，已经在 sohu的线上系统部署使用


# 方案一 手工切换



## 要点

1. 主从数据一致: 主库发生故障时主从数据不一致。 5.5 半同步
[aliyun](http://help.aliyun.com/view/11108238_13440406.html),[netease](http://blog.csdn.net/jiao_fuyou/article/details/16899107)


2. 从库同步延迟:
    * 从库数据滞后。slave 状态检查
    * 主从切换后等待日志回放完毕。手工切


3. 选主: 手工指定读写角色，从库选主权重等于0



## 场景

1. DBProxy 切换:
    * 读写角色不变


2. 从库切换: down 或延迟
    * dbproxy 将读请求切道主库


3. 主库切换: down
    * dbproxy 写请求失败，只读
    * 从库同步延迟状态
    * 重置复制关系 MM
    * 设置只读
    * dbproxy 设置主库 rwweight


4. 脑裂: ping 网关


5. 重复切换：


6. 监控

后端数据库角色变化



## 功能模块

1. dbproxy 高可用
    * dbproxy 状态检查
    * dbproxy 故障切换
    * 虚IP切换
    * 配置文件同步
    * (keepalived)


2. rw backend 高可用
    * rwbackend 状态检查 定时  触发切换逻辑
        * 降级
        * 选主
        * 提升
    * 根据主从设置 read_only 定时
    * (keepalived)


3. ro backend 高可用
    * backend 状态检查
    * 切换
    * (dbproxy)



## 主要场景操作步骤

1. 启 dbproxy
    * 根据配置文件指定的主库 rw
        * 主库 rw_weigh 权重 x, 从库 rw_weight 权重0


2. dbproxy down
    * dbproxy高可用 切换
    * 同 1.


3. 主机 down
    * dbproxy down
        * 同 2.
    * backend 状态检查
        * rw 的状态是 down
    * 事前检查
        * 检查 rw 主机连接不上
        * 检查 ro db 联通
    * 降级
        * rw 节点权重设置为 0
        * rw 设为 read_only=1 failed
    * 选主
        * 选另一个节点即当前 ro
    * 提升
        * 等待应用日志 io stop, sql start, 应用完日志  (日志可能不完整)
        * 修改权重 2 配置文件
        * 关闭 read only=0


4. 主库 down
    * rwbackend 状态检查
        * rw 的状态是 down
    * 事前检查
        * 检查 rw db 连接不上, 主机连上
    * 降级
        * rw 节点权重设置为 0
        * rw 设为 read_only=1 failed
    * 选主
        * 选从库
    * 提升
        * 拷日志??
        * 等待应用日志
        * 修改权重 2
        * read only=0


5. 手工切 switchover
    * 事前检查
        * 检查 rw,ro 连接
    * 降级
        * 将rw设置为 read only
        * 权重设置为 0
    * 选主
        * 选另一个节点
    * 提升
        * 等待应用日志
        * 修改权重
        * read only=0





# 方案二 自动切换



## 场景介绍

1. DBProxy 切换:
    * 读写角色不变 （'''靠配置文件的同步来保证这一点，依赖读写权重实现主备角色的维持。需要确认 dbproxy 代码是否满足这种要求？基本确认是可行的'''）


2. 从库切换: down 或延迟
    * dbproxy将对应的节点从读负载均衡的列表中摘除（可以通过设置权重或者设置 dbproxy 的状态的方式进行），读请求切到主库


3. 主库切换: down
    * dbproxy 检测 rw 节点状态失败，将 rw 节点状态设置为 down
    * 外部脚本选取新主库
    * 从库同步延迟状态
    * 重置复制关系 MM
    * 设置只读
    * dbproxy 设置主库 rw weight


4. 脑裂: 引入第三方仲裁，ping 网关


5. 重复切换：暂时没考虑



## 结合 keepalived 有如下几个功能模块

1. dbproxy 高可用
    * dbproxy 状态检查(包括 dbproxy 进程的状态及 backend 是否可用)，通过返回结果给 keepalived 触发虚 IP 的切换
    * dbproxy 故障切换,实现的功能包括如下几点：
        * 虚 IP 切换
        * 配置文件同步
        * (keepalived)

    脚本实现时，包括三个动作
    > to_master: notify_master "/etc/keepalived/dbproxy_notify.sh --state=master --vip=192.168.1.2 --gw=192.168.1.200"
    >
    > 确认虚ip可用，启动并确认dbproxy正常运行
    >
    >
    > to_slave : notify_backup "/etc/keepalived/dbproxy_notify.sh --state=backup --vip=192.168.1.2 --gw=192.168.1.200"
    >
    > 不做任何动作
    >
    >
    > to_fault : notify_fault "/etc/keepalived/dbproxy_notify.sh --state=fault --vip=192.168.1.2 --gw=192.168.1.200"
    >
    > stop dbproxy, 并确认删除虚ip
    >


2. rw backend高可用
    * rwbackend 状态检查 定时  触发切换逻辑
    * 需要进行主备切换的情形包括：
        * 刚开始重启，backend 角色都是 slave;
        * 运行过程中 master 宕了，状态成 down
    * 主库切换需要进行如下的操作
        * 降级（dbproxy 里面会做一部分将 rw 节点设置为 down）
        * 选主（脚本中选取另外一个 up 的 slave 为主库）
        * 提升，具体过程如下

            > 等待新主库日志应用；
            >
            > 将新主库的 readonly 关闭；
            >
            > 设置其写权重为 非0；（便于后续 dbproxy 选主）
    * 根据主从设置 read_only 定时
    * (keepalived)


3. ro backend 高可用
    * backend 状态检查
    * 切换
    * (dbproxy)



## 主要场景操作步骤

1. 启 dbproxy
    * 根据配置文件指定的主库 rw
        * 主库 rw_weigh 权重 x, 从库 rw_weight 权重 0


2. dbproxy down
    * dbproxy 高可用 切换
    * 同 1.


3. 主机down
     * dbproxy down
         * 同2.2
     * backend状态检查
         * rw的状态是down
     * 事前检查
         * 检查rw主机连接不上
         * 检查ro db联通
     * 降级
         * rw节点权重设置为0
         * rw设为read_only=1 failed
     * 选主
     *    * 选另一个节点即当前ro
     * 提升
         * 等待应用日志 io stop, sql start, 应用完日志  (日志可能不完整)
         * 修改权重2 配置文件
         * 关闭read only=0


4. 主库 down

    * rwbackend 状态检查
        * rw 的状态是 down
    * 事前检查
        * 检查 rw db 连接不上, 主机连上
    * 降级
        * rw 节点权重设置为 0
        * rw 设为 read_only=1 failed
    * 选主
        * 选从库
    * 提升
        * 拷日志??
        * 等待应用日志
        * 修改权重2
        * read only=0


5. 手工切 switchover

    * 事前检查
        * 检查 rw,ro 连接
    * 降级
        * 将rw设置为 read only
        * 权重设置为 0
    * 选主
        * 选另一个节点
    * 提升
        * 等待应用日志
        * 修改权重


#配置说明
##haconf文件说明
1.格式说明

* 第一列：N或者Y, Y表示维护模式。维护模式就是跳过keepalived的检查和提升逻辑，这样你可以手工控制一切操作
* 第二列：dbproxy。 表示是dbproxy类型
* 第三列：mysql的目录
* 第四列：保留
* 第五列：MASTER_IP
* 第六列：SLAVE_IP
* 第七列：N或者Y, Y表示错误模式。错误模式下服务会切换到另外一台机器上，功能类似于停止本地的keepalived
* 第八列：和keepalived.conf的vrrp_instance的名字需要一致
* 第九列：保留
* 第十列：保留

2.举例

N dbproxy /usr 3001 null 192.168.1.1,192.168.1.2 N vi_dbproxy_73 null null
