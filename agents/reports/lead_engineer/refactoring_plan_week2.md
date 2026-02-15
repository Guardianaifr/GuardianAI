# Refactoring Plan (Week 2)

**Goal**: Clean up instrumentation technical debt and improve testability.

## 1. Implement Timing Decorator
**Problem**: Passing `timings` dict everywhere.
**Solution**:
```python
def measure_latency(component_name):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            start = time.perf_counter()
            result = func(self, *args, **kwargs)
            duration = (time.perf_counter() - start) * 1000
            # Store in thread-local storage or request context
            g.timings[component_name] = duration
            return result
        return wrapper
    return decorator
```
**Effort**: Medium (requires refactoring all 5 helper methods).

## 2. Config Object Migration
**Problem**: Loose dict access for config.
**Solution**:
Create `GuardianConfig` class:
```python
class GuardianConfig(BaseModel):
    listen_port: int = 8080
    security_mode: Literal['strict', 'balanced'] = 'balanced'
    # ...
```
**Effort**: High (touches all files).

## 3. PII Scanner Abstraction
**Problem**: Presidio dependency issues.
**Solution**:
Create `PIIScanner` abstract base class.
- `PresidioScanner` implementation.
- `RegexScanner` implementation.
Load implementation based on available libraries/config.
**Effort**: Medium.

## Recommendation
Proceed with **Item 1 (Timing Decorator)** in Week 3 to clean up the codebase before adding more features.
