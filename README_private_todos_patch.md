# Private To-Dos — Final Update

- Removed **Assign to myself** from the Manager create form.
- Added **Add Private To-Do (Manager)** section with modal description editor.
- Updated **User Add Private To-Do** form to use the same **modal description editor UI** as the manager.
- Ensured **My Private To-Do List** is separate for both roles and renders description column; clicking a description in lists opens a modal (existing behavior).
- Kept all privacy logic: private tasks (`is_private=True`) are only visible to their owner; department views exclude them.

## Routes
- Manager departmental task creation: `/tasks/create` (requires Department + Assignee)
- Private To-Do creation for any user (including manager): `POST /tasks/self/create`

## DB Migration
On start and on `/seed`, app attempts to add the `is_private` column if missing.

