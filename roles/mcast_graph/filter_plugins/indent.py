class FilterModule(object):
    def lower_all(self, table):
        objs = []
        for row in table:
            temp_dict = {}
            for k, v in row.items():
                temp_dict[k.lower()] = v
            objs.append(temp_dict)
        return objs

    def indent_block(self, value, indent=2):
        return "\n".join([' '*indent + l for l in value.splitlines()])

    def filters(self):
        return {
            'indent_block': self.indent_block,
            'lower_all': self.lower_all,
        }
