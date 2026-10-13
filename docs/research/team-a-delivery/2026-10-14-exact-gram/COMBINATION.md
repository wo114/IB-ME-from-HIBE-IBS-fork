# ABB + Luo 组合验收入口（WIP，尚未运行完整组合）

`experiments/research/abb_rom/saved_combo_probe.py` 读取一份已完成、源指纹未变的真实ABB实例，不重新生成或替换HIBE。Luo独立使用C64B/compact和默认系统随机数，公共框架复用Hybrid/BYTEAUTH。

诚实场景使用Bob/Alice的已发密钥，32 B应用消息、86/86 B内层身份和32 B随机seed。三个身份错配分别把密文加密到Carol/Alice、Bob/Charlie和Carol/Charlie，再用同一真实Bob/Alice接收路径解密；不以标签比较或替代密钥代替真实数学执行。后续执行五类对象及组合状态恢复、截断/追加/重复/版本拒绝、密文/OTS签名篡改、新OTS重新签名、可规范解析的IBS签名修改与随机伪造。每次原始ABB解密仍有256次新SamplePre。

仅当原语收据为完整32 B/86 B路径时才能启动。对缺失、失败、源变化、重复根、缩小消息或身份的拒绝门测试实际8 passed（1.24秒），这不是组合通过。真实执行命令为：

```sh
export PATH="$HOME/.cache/ibme-native-tools/flatter-d2b8026/bin:$PATH"
export IBME_EXACT_GRAM_EXECUTABLE="$HOME/.cache/ibme-native-tools/exact-gram-v1/bin/ibme-exact-gram"
export PYTHONPATH="$PWD/src:$PWD"
export OMP_NUM_THREADS=8 OPENBLAS_NUM_THREADS=1
~/miniconda3/envs/sage/bin/python -m experiments.research.abb_rom.saved_combo_probe \
  --abb-private-directory test-results/abb-q80-native/private \
  --private-output-directory test-results/abb-q80-luo-private \
  --baseline-commit '<实际冻结提交>'
```

所有秘密对象、临时签名、密文和错误值留在忽略的私有目录；公开收据仅含配置、长度、阶段、检查结果和源码哈希。主私钥原文件只读，缓存恢复不发新密钥。没有执行结果前保持WIP；n=1 ABB为安全负控，Luo未准入，组合也保持none/false，测试不能证明密码学安全。
