import yaml
class Loader(yaml.SafeLoader):
    pass

def tag(loader, tag, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)
Loader.add_multi_constructor('!', tag)
data = yaml.load(open('template/template.yaml', encoding='utf-8-sig'), Loader=Loader)
print('SAM YAML parse: OK; resources:', ', '.join(data['Resources']))
