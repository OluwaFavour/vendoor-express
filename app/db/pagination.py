from datetime import datetime
from typing import Type

from annotated_types import T
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


async def paginate_query(
    session: AsyncSession,
    model: Type[T],
    filter_conditions: dict,
    limit: int,
    after: datetime | None = None,
    before: datetime | None = None,
    order_by_field: str = "created_at",
    include_total: bool = False,
) -> tuple[list[T], int | None, datetime | None, datetime | None]:
    """
    Paginate a query on a given SQLAlchemy model.
    Args:
        session (AsyncSession): The SQLAlchemy async session to use for the query.
        model (Type[T]): The SQLAlchemy model to query.
        filter_conditions (dict): A dictionary of conditions to filter the query.
        limit (int): The maximum number of items to return.
        after (datetime | None, optional): A datetime to filter items created after. Defaults to None.
        before (datetime | None, optional): A datetime to filter items created before. Defaults to None.
        order_by_field (str, optional): The field to order the query by. Defaults to "created_at".
        include_total (bool, optional): Whether to include the total count of items. Defaults to False.
    Returns:
        tuple[list[T], int | None, datetime | None, datetime | None]: A tuple containing:
            - A list of items of type T.
            - The total count of items if include_total is True, otherwise None.
            - The next cursor for pagination, or None if there are no more items.
            - The previous cursor for pagination, or None if there are no previous items.
    """
    # Create the base query with the model and filter conditions
    query = select(model).filter_by(**filter_conditions)

    # Get the field to order by from the model
    order_field = getattr(model, order_by_field)

    # Apply the 'after' filter if provided, ordering by ascending order
    if after:
        query = query.where(order_field > after).order_by(order_field.asc())
    # Apply the 'before' filter if provided, ordering by descending order
    elif before:
        query = query.where(order_field < before).order_by(order_field.desc())
    # If no 'after' or 'before' filter is provided, order by descending order
    else:
        query = query.order_by(order_field.desc())

    # Limit the query to one more than the requested limit to check for the next cursor
    query = query.limit(limit + 1)

    # Execute the query
    result = await session.execute(query)

    # Fetch all the items from the result
    items = result.scalars().all()

    # Initialize total to None
    total = None
    if include_total:
        # Create a query to count the total number of items matching the filter conditions
        total_query = (
            select(func.count()).select_from(model).filter_by(**filter_conditions)
        )
        # Execute the total count query
        total_result = await session.execute(total_query)
        # Get the total count from the result
        total = total_result.scalar()

    # Initialize cursors to None
    next_cursor = None
    previous_cursor = None

    # Check if the number of items exceeds the limit to determine the next cursor
    if len(items) > limit:
        # Trim the items to the requested limit
        items = items[:limit]
        # Set the next cursor to the order_by_field value of the last item
        next_cursor = getattr(items[-1], order_by_field)
    # If there are items and an 'after' filter was applied, determine the previous cursor
    elif len(items) > 0 and after:
        # Create a query to find the previous cursor
        prev_query = (
            select(order_field)
            .filter_by(**filter_conditions)
            .where(order_field < getattr(items[0], order_by_field))
            .order_by(order_field.desc())
            .limit(1)
        )
        # Execute the previous cursor query
        prev_result = await session.execute(prev_query)
        # Set the previous cursor to the result of the query
        previous_cursor = prev_result.scalar()

    # If a 'before' filter was applied and there are items, reverse the items list
    if before and items:
        items = items[::-1]

    return items, total, next_cursor, previous_cursor
