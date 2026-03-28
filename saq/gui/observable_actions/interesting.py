from saq.constants import ACTION_MARK_INTERESTING, ACTION_UNMARK_INTERESTING
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionMarkInteresting(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_MARK_INTERESTING
        self.description = "Mark as interesting"
        self.action_path = 'analysis/observable_actions/mark_interesting.html'
        self.icon = 'star'


class ObservableActionUnmarkInteresting(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_UNMARK_INTERESTING
        self.description = "Unmark as interesting"
        self.action_path = 'analysis/observable_actions/unmark_interesting.html'
        self.icon = 'star-fill'
