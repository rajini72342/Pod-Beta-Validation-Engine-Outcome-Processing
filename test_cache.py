import pytest

from outcome_classifier.cache import QueryCache, build_cache_key


class TestBuildCacheKey:
    def test_stable_for_same_inputs(self):
        k1 = build_cache_key(
            action_id="a1", technique_ref="T1486", rule_id="r1",
            expected_observable="obs", expected_fields=["b", "a"],
        )
        k2 = build_cache_key(
            action_id="a1", technique_ref="T1486", rule_id="r1",
            expected_observable="obs", expected_fields=["a", "b"],
        )
        assert k1 == k2  # field order shouldn't matter (sorted internally)

    def test_differs_for_different_inputs(self):
        k1 = build_cache_key(
            action_id="a1", technique_ref="T1486", rule_id="r1",
            expected_observable="obs", expected_fields=["a"],
        )
        k2 = build_cache_key(
            action_id="a2", technique_ref="T1486", rule_id="r1",
            expected_observable="obs", expected_fields=["a"],
        )
        assert k1 != k2

    def test_key_has_stable_prefix(self):
        k = build_cache_key(
            action_id="a1", technique_ref="T1486", rule_id="r1",
            expected_observable="obs", expected_fields=[],
        )
        assert k.startswith("validation-engine:query:")


class TestQueryCacheInMemory:
    @pytest.mark.asyncio
    async def test_defaults_to_in_memory_when_no_redis_url(self):
        cache = QueryCache()
        assert cache.using_redis is False

    @pytest.mark.asyncio
    async def test_miss_then_set_then_hit(self):
        cache = QueryCache()
        key = "k1"
        assert await cache.get(key) is None
        assert cache.stats["misses"] == 1
        await cache.set(key, {"x": 1})
        result = await cache.get(key)
        assert result == {"x": 1}
        assert cache.stats["hits"] == 1

    @pytest.mark.asyncio
    async def test_ttl_expiry(self):
        cache = QueryCache()
        await cache.set("k1", {"x": 1}, ttl_seconds=0)
        # A zero-second TTL should already be expired.
        import asyncio

        await asyncio.sleep(0.01)
        assert await cache.get("k1") is None

    @pytest.mark.asyncio
    async def test_close_does_not_raise(self):
        cache = QueryCache()
        await cache.set("k1", {"x": 1})
        await cache.close()

    @pytest.mark.asyncio
    async def test_backend_get_failure_is_a_miss_not_an_exception(self):
        cache = QueryCache()

        async def boom(key):
            raise RuntimeError("backend down")

        cache._backend.get = boom
        result = await cache.get("k1")
        assert result is None
        assert cache.stats["misses"] == 1

    @pytest.mark.asyncio
    async def test_backend_set_failure_is_swallowed(self):
        cache = QueryCache()

        async def boom(key, value, ttl):
            raise RuntimeError("backend down")

        cache._backend.set = boom
        # Should not raise.
        await cache.set("k1", {"x": 1})
