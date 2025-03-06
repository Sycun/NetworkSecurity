# 测试覆盖率报告生成指南

## 生成步骤
1. 安装依赖：
```bash
pip install -r requirements.txt
pip install pytest coverage
```

2. 运行测试并生成覆盖率报告：
```bash
coverage run -m pytest tests/

# 生成文本报告
coverage report

# 生成XML格式报告（适用于CI系统）
coverage xml

# 生成HTML可视化报告
coverage html
```

3. 查看报告：
- 文本报告：控制台直接查看
- XML报告：coverage.xml
- HTML报告：查看htmlcov目录中的index.html

## 注意事项
- 生成的.coverage、coverage.xml和htmlcov/目录已加入.gitignore
- 建议在CI/CD流水线中配置覆盖率报告生成
- 不要将覆盖率数据提交到版本库，推荐使用CI系统的制品存档功能保存历史记录