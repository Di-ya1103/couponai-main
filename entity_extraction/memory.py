class SimpleMemory:
    def __init__(self):
        self.state = {}

    def update(self, entities):
        for k, v in entities.items():
            if v:
                self.state[k] = v

    def get(self):
        return self.state

memory = SimpleMemory()
