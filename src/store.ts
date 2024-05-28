import { JSONArray, JSONValue, JSONObject, JSONPrimitive } from "./json-types";

export type Permission = "r" | "w" | "rw" | "none";

export type StoreResult = Store | JSONPrimitive | undefined;

export type StoreValue =
	| JSONObject
	| JSONArray
	| StoreResult
	| (() => StoreResult);

export interface StoreRecord {
	[key: string]: StoreValue;
}

export interface IStore {
	defaultPolicy: Permission;
	allowedToRead(key: string): boolean;
	allowedToWrite(key: string): boolean;
	read(path: string): StoreResult;
	write(path: string, value: StoreValue): StoreValue;
	writeEntries(entries: JSONObject): void;
	entries(): JSONObject;
}

export function Restrict(permission: Permission = "none") {
	return function (
		target: Store & { __permissions?: { [key: string]: Permission } },
		propertyKey: string,
	) {
		// Create a new object with the current store and its data
		target.__permissions = target.__permissions || {};
		target.__permissions[propertyKey] = permission;
	};
}

export class Store implements IStore {
	private _data: StoreRecord = {};
	private _permissions: { [key: string]: Permission } = {};
	defaultPolicy: Permission = "rw";

	constructor() {
		// Get the prototype of the current instance
		const proto = Object.getPrototypeOf(this);
		// Create a new object with the permissions of the current prototype instance
		this._permissions = Object.create(proto.__permissions || {});
	}

	private _getPermissions(key: string, store: Store = this): Permission {
		const keys = key.split(":");
		if (!keys.length) return store.defaultPolicy;
		// Shift the first key from the array and assign it to currentKey
		const currentKey = keys.shift() || keys[0];

		let nextStore = store[currentKey as keyof Store] as StoreValue;
		if (nextStore instanceof Store) {
			// If the value is a Store, recursively call _getPermissions
			return nextStore._getPermissions(keys.join(":"), nextStore);
		} else if (typeof nextStore === "function") {
			// If the value is a function, execute it and recursively call _getPermissions
			nextStore = nextStore() as Store;
			nextStore._getPermissions(keys.join(":"), nextStore);
		}

		// If the value is not a Store, return the permission from the current store
		return store._permissions[currentKey] || store.defaultPolicy;
	}

	private _getPropertyByPath(path: string): StoreResult {
		const keys = path.split(":");
		// Create a new object with the current store and its data
		const currentStore = { ...this, ...this._data };

		let nextStore = currentStore[keys[0]];
		if (nextStore && nextStore instanceof Store) {
			// If the value is a Store, recursively call _getPropertyByPath
			return nextStore._getPropertyByPath(keys.slice(1).join(":"));
		} else if (typeof nextStore === "function") {
			// If the value is a function, execute it.
			nextStore = nextStore();
			if (nextStore instanceof Store)
				// If the value is a Store, recursively call _getPropertyByPath
				return nextStore._getPropertyByPath(keys.slice(1).join(":"));
		}

		// If the value is not a Store, return the value
		if (!keys.length || !keys[0].length) return this;

		// Reduce the keys array to get the value of the last key
		return keys.reduce<StoreResult>(
			(store, key) => store?.[key as keyof StoreResult] || store,
			currentStore,
		);
	}

	private _setPropertyByPath(path: string, value: StoreValue): void {
		const keys = path.split(":");

		const nextStore = this[keys[0] as keyof Store];
		if (nextStore && nextStore instanceof Store) {
			// If the value is a Store, recursively call _setPropertyByPath
			return nextStore._setPropertyByPath(keys.slice(1).join(":"), value);
		} else if (typeof value === "object") {
			// If the value is an object, create a new Store and assign the value to it
			return Object.entries(value as JSONObject).forEach(([key, val]) => {
				const newStore = new Store();
				newStore._setPropertyByPath(key, val); // Recursively call _setPropertyByPath
				this._data[keys[0]] = newStore; // Assign the new Store to the current store
			});
		}

		this._data[keys[0]] = value;
	}

	private _correctType(value: StoreValue): boolean {
		return (
			typeof value !== "function" &&
			value !== undefined &&
			typeof value !== "object"
		);
	}

	allowedToRead(key: string): boolean {
		const permission = this._getPermissions(key);
		return permission.includes("r");
	}

	allowedToWrite(key: string): boolean {
		const permission = this._getPermissions(key);
		return permission.includes("w");
	}

	read(path: string): StoreResult {
		if (!this.allowedToRead(path)) throw new Error("Access denied");
		return this._getPropertyByPath(path);
	}

	write(path: string, value: StoreValue): StoreValue {
		if (!this.allowedToWrite(path)) throw new Error("Access denied");
		this._setPropertyByPath(path, value);
		return value;
	}

	writeEntries(entries: JSONObject): void {
		for (const [key, value] of Object.entries(entries)) {
			this.write(key, value);
		}
	}

	entries(): JSONObject {
		return Object.entries({ ...this._data, ...this })
			.filter(
				([key, value]) =>
					this.allowedToRead(key) && this._correctType(value),
			)
			.reduce<JSONObject>((acc, [key, value]) => {
				acc[key] = value as JSONValue;
				return acc;
			}, {});
	}
}
