from saq.gui.observable_actions.base import ObservableAction


class ObservableActionAddComment(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = 'add_comment'
        self.description = "Add Comment"
        self.action_path = 'analysis/observable_actions/add_comment.html'
        self.icon = 'chat-dots'
