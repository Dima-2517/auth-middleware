import { MiddlewareFn } from 'type-graphql';
export enum Role {
	Admin = 'admin',
	SuperAdmin = 'superAdmin',
}
export function GQLUserRole(permissionNames: string | string[]): MiddlewareFn {
	return async ({ info, context, args }, next) => {
		// Throw an error if JWT verification fault.
		if (!context['user']) throw new Error('Permission denied.');
		// Check if roleName is string type.
		if (typeof permissionNames === 'string') {
			try {
				if (permissionNames === Role.SuperAdmin) {
					if (!context['user'][permissionNames]) throw new Error('Permission denied.');
				} else {
					if (!context['user']['permissions'].find((permission) => permission === permissionNames))
						throw new Error('Permission denied.');
				}
			} catch {
				throw new Error('Permission denied.');
			}
		} else {
			try {
				// If roleName array of strings.
				const permissions = permissionNames.map((role: string) => {
					if (role === Role.SuperAdmin) {
						return !!context['user'][role];
					} else {
						return !!context['user']['permissions'].find((permission) => permission === role);
					}
				});
				if (!permissions.find((permission: boolean) => permission)) throw new Error('Permission denied.');
			} catch {
				throw new Error('Permission denied.');
			}
		}

		return await next();
	};
}
