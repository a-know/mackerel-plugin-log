# mackerel-plugin-log

## Install

```sh
% mkr plugin install a-know/mackerel-plugin-log
```

## Setting

```
[plugin.metrics.log-detect]
command = '''
/path/to/mackerel-plugin-log --file /path/to/app.log --pattern "ERROR" --exclude "retry"
'''
```
