import asyncio

async def task1():
    print("Task 1 started")
    await asyncio.sleep(3)
    print("Task 1 done")

async def task2():
    print("Task 2 started")
    await asyncio.sleep(2)
    print("Task 2 done")

async def main():
    await task1()
    await task2()

async def main():
    t1 = asyncio.create_task(task1())
    t2 = asyncio.create_task(task2())
    await t2

asyncio.run(main())
