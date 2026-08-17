# Trust domain 轮换

`arkret.trust_domain` 把 peer 与恢复授权 transcript 绑定到当前
部署。变更该值会令使用旧 trust domain 签发、仍在途的证明与
会话失效。

轮换前：

1. 记录当前配置值，并确认其与 `/_arkret/describe`
   返回的一致。
2. 暂停或拒绝以旧值签发、尚未完成的恢复批准请求。
3. 对数据库做快照，并将旧配置与该快照一起保存。
4. 与 Principal Server 运维人员协调，使其在切换之后拒绝
   过期恢复证明。

轮换过程中：

1. 在 `arkret.trust_domain` 中写入新值。
2. 重启一个 `coauth` 副本，确认
   `/_arkret/describe` 公布了新值。
3. 滚动重启其余副本。
4. 通过设备恢复流程重新签发 reset 证明。受影响的证明族
   包括 `principal_signing`、`recovery_unlock`、
   `device_quorum` 与 `trusted_recovery_service`。
5. 在新证明可用之后再完成 root-anchored 设备 re-anchor。

不要把旧 reset 证明重新喂给新的 trust domain。它们必须失败，
因为其规范 transcript 是为另一个部署作用域签名的。
