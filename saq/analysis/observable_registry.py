import logging
from datetime import datetime
from typing import Dict, Optional, Callable, Any

from saq.analysis.errors import ExcessiveFileDataSizeError
from saq.constants import F_FILE
from saq.environment import get_global_runtime_settings
from saq.analysis.observable import Observable

#
# this is what used to be called the "observable store" in the RootAnalysis class
#

class ObservableRegistry:
    """Manages the lifecycle and storage of observables within an analysis context."""
    
    def __init__(self,
                 observable_limits: Optional[Dict[str, int]] = None,
                 size_limit: Optional[int] = None,
                 get_total_size: Optional[Callable[[], int]] = None,
                 on_modified: Optional[Callable[[], None]] = None):
        """
        Initialize the ObservableRegistry.

        Args:
            observable_limits: Per-type observable limits. If None, uses global config.
            size_limit: Maximum analysis disk size allowed. If None, no size checking.
            get_total_size: Function to get current total size for size checking.
            on_modified: Callback function to call when registry is modified.
        """
        self._store: Dict[str, Observable] = {}
        self._observable_limits = observable_limits
        self._size_limit = size_limit
        self._get_total_size = get_total_size
        self._on_modified = on_modified
        
    @property
    def store(self) -> Dict[str, Observable]:
        """Returns the internal observable store."""
        return self._store
    
    def get_by_id(self, uuid: str) -> Optional[Observable]:
        """Returns the Observable object for the given uuid."""
        return self._store.get(uuid)
    
    def get_by_spec(self, o_type: str, o_value: Any, o_time: Optional[datetime] = None) -> Optional[Observable]:
        """Returns the Observable object by type and value, and optionally time, or None if it cannot be found."""
        from saq.analysis.observable import Observable
        target = Observable(o_type, o_value, o_time)
        for o in self._store.values():
            if o == target:
                return o
        return None
    
    def get_all(self) -> list[Observable]:
        """Returns the list of all Observables in the registry."""
        return list(self._store.values())
    
    def get_by_type(self, o_type: str) -> list[Observable]:
        """Returns the list of Observables that match the given type."""
        return [o for o in self._store.values() if o.type == o_type]
    
    def find(self, criteria: Callable[[Observable], bool]) -> Optional[Observable]:
        """Returns the first observable that matches the criteria, or None if nothing is found."""
        result = self._find_observables(criteria)
        if result:
            return result[0]
        else:
            return None
    
    def find_all(self, criteria: Callable[[Observable], bool]) -> list[Observable]:
        """Returns all observables that match the criteria."""
        return self._find_observables(criteria)
    
    def _find_observables(self, criteria: Callable[[Observable], bool]) -> list[Observable]:
        """Internal method to find observables by criteria."""
        result = []
        for observable in self._store.values():
            if criteria(observable):
                result.append(observable)
        
        return result
    
    def record(self, observable: Observable) -> Optional[Observable]:
        """
        Records the given observable into the store if it does not already exist.
        Returns the new one if recorded, the existing one if it already exists,
        or None if the per-type limit has been reached.
        """
        from saq.analysis.observable import Observable
        assert isinstance(observable, Observable)

        # ACE must never store an observable with an empty value. Generic observable
        # types (user, and any unknown DefaultObservable type) do not reject empty or
        # whitespace-only values on their own, so guard here at the single storage
        # chokepoint that every live add funnels through.
        value = observable.value
        if value is None or (isinstance(value, str) and not value.strip()):
            logging.warning("refusing to add observable type %s with empty value", observable.type)
            return None

        # Check if observable already exists
        for o in self._store.values():
            if o == observable:
                logging.debug("returning existing observable {} ({}) [{}] <{}> for {} ({}) [{}] <{}>".format(
                    o, id(o), o.uuid, o.type, observable, id(observable), observable.uuid, observable.type))
                return o

        # Check per-type observable limits
        observable_limits = self._observable_limits
        if observable_limits is None:
            observable_limits = get_global_runtime_settings().observable_limits

        if observable_limits:
            type_limit = observable_limits.get(observable.type)
            if type_limit is not None:
                current_count = len(self.get_by_type(observable.type))
                if current_count >= type_limit:
                    logging.warning(
                        "observable type %s has reached its limit of %s",
                        observable.type, type_limit,
                    )
                    return None
        
        # Check size limit for file observables
        from saq.observables.file import FileObservable

        if (self._size_limit and 
            self._get_total_size and 
            observable.type == F_FILE and 
            isinstance(observable, FileObservable) and 
            observable.size is not None):
            
            current_size = self._get_total_size()
            if current_size is not None:
                target_size = observable.size + current_size
                if target_size > self._size_limit:
                    observable.add_tag('analysis_too_large')
                    logging.warning(f"target_size {target_size} > size_limit {self._size_limit}")
                    raise ExcessiveFileDataSizeError(f'analysis is too large to add {observable.value}')
        
        # Record the observable
        self._store[observable.uuid] = observable
        logging.debug("recorded observable {} with id {}".format(observable, observable.uuid))
        
        # Notify modification
        if self._on_modified:
            self._on_modified()
        
        return observable
    
    def record_by_spec(self, o_type: str, o_value: Any, o_time: Optional[datetime] = None, 
                      sort_order: int = 100, volatile: bool = False) -> Optional[Observable]:
        """
        Records the given observable into the store if it does not already exist.
        Returns the new one if recorded or the existing one if not.
        """
        from saq.observables import create_observable
        
        assert isinstance(o_type, str)
        assert o_time is None or isinstance(o_time, str) or isinstance(o_time, datetime)
        
        # Create a temporary object to make use of any defined custom __eq__ ops
        observable = create_observable(o_type, o_value, o_time=o_time, sort_order=sort_order, volatile=volatile)
        if observable is None:
            return None
        
        return self.record(observable)
    
    def remove(self, observable_id: str) -> bool:
        """
        Removes an observable from the registry.
        Returns True if removed, False if not found.
        """
        if observable_id in self._store:
            del self._store[observable_id]
            if self._on_modified:
                self._on_modified()
            return True
        return False
    
    def clear(self):
        """Clears all observables from the registry."""
        self._store.clear()
        if self._on_modified:
            self._on_modified()
    
    def __len__(self) -> int:
        """Returns the number of observables in the registry."""
        return len(self._store)
    
    def __contains__(self, observable_id: str) -> bool:
        """Returns True if the observable ID exists in the registry."""
        return observable_id in self._store
    
    def __iter__(self):
        """Allows iteration over the observables in the registry."""
        return iter(self._store.values()) 